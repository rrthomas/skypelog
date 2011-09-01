#! /usr/bin/env lua
prog = {
  name = "skypelog",
  banner = "skypelog 0.13 (01 Sep 11) by Reuben Thomas (rrt@sc3d.org)",
  purpose = "Parse a Skype chat log",
}

-- Based on original decoding work, with help from http://www.patrickmin.com/linux/tip.php?name=skype_timestamp


require "std"


-- Turn a little-endian word into a number
function lword (s)
  local res = 0
  for i = string.len (s), 1, -1 do
    res = res * 256 + string.byte (s, i)
  end
  return res
end

-- Turn a big-endian word into a number
function bword (s)
  local res = 0
  for i = 1, string.len (s) do
    res = res * 256 + string.byte (s, i)
  end
  return res
end

-- Turn a little-endian word into a hex string
function hex (s)
  local res = ""
  for i = 1, string.len (s) do
    res = res .. string.format ("%.2x", string.byte (s, i))
  end
  return res
end

-- Process a file
function main (file, number)
  local rec = {n = 0}
  io.input (file)
  local _, _, num = string.find (file, ".-(%d+)%.dbb$")
  local reclen = tonumber (num) + 8
  while true do
    local s = io.read (reclen)
    if not s then
      break
    end
    assert (string.sub (s, 1, 4) == "l33l")
    local len = lword (string.sub (s, 5, 8))
    local body = string.sub (s, 9, 9 + len - 1)
    assert (string.len (body) == len)
    local seq = lword (string.sub (body, 1, 4))
    local _, to, name = string.find (body, "(%Z*)", 13)
    local type = hex (string.sub (body, to + 2, to + 8)) -- 00c9010103d001 = authorisation request/reply, 00c9010203d001 = message
    assert (type == "00c9010103d001" or type == "00c9010203d001")
    local _, to, mess = string.find (body, "(%Z*)", to + 9)
    -- Indefinite length (little-endian, top bit is 1 until final byte)
    local ctime = 0
    local i = to + 5
    while bit.band (string.byte (body [i]), 128) == 128 do
      ctime = ctime + bit.band (string.byte (body [i]), 127) * (2 ^ ((i - (to + 5)) * 7))
      i = i + 1
    end
    local datestamp = string.chomp (io.shell ("ctime2date " .. tostring (ctime + 1073745342)))
    local rest = i
    local from, to, alias = string.find (body, "\003\168\001(%Z*)", to + 3)
    local bin1, bin2
    if from then
      bin1 = hex (string.sub (body, rest, from - 1))
      bin2 = hex (string.sub (body, to + 2, -1))
    else
      bin1 = hex (string.sub (body, rest, -1))
    end
    local _, _, dir = string.find (bin1, "00cd010(.)")
    if not dir then
      _, _, dir = string.find (bin2, "00cd010(.)")
    end
    assert (dir)
    if dir and bit.band (dir, 4) == 0 then
      dir = "out"
    else
      dir = "in"
    end
    rec[seq] = {
      seq = seq,
      name = name,
      mess = mess,
      alias = alias,
      datestamp = datestamp,
      dir = dir,
    }
    print (rec[seq])
  end
  print (#rec .. " records")
end


-- Main routine
getopt.processArgs ()
if #arg == 0 then
  getopt.usage ()
  os.exit (1)
end
io.processFiles (main)


-- Changelog

--   0.1  04aug04 Program started
--   0.11 06sep04 Refined interpretation of message files
--   0.12 08sep04 Now have direction of message
--   0.13 01sep11 Convert to Lua 5.1, update stdlib usage, update purpose, decode date

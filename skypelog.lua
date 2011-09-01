#! /usr/bin/lua
prog = {
  name = "skypelog",
  banner = "skypelog 0.12 (08 Sep 04) by Reuben Thomas (rrt@sc3d.org)",
  purpose = "Turn a Skype log into text",
}


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
    if not s then break end
    assert (string.sub (s, 1, 4) == "l33l")
    local len = lword (string.sub (s, 5, 8))
    local body = string.sub (s, 9, 9 + len - 1)
    assert (string.len (body) == len)
    local seq = lword (string.sub (body, 1, 4))
    local bin0 = hex (string.sub (body, 5, 8)) -- always 41070009, 41080009 or 41090009 so far (07, 08, 09 is the month!)
    assert (bin0 == "41070009" or bin0 == "41080009" or bin0 == "41090009")
    local bin1 = hex (string.sub (body, 9, 12)) -- always 0303a401 so far
    assert (bin1 == "0303a401")
    local _, to, name = string.find (body, "(%Z*)", 13)
    local type = hex (string.sub (body, to + 2, to + 8)) -- 00c9010103d001 = authorisation request/reply, 00c9010203d001 = message
    local _, to, mess = string.find (body, "(%Z*)", to + 9)
    local bin2 = hex (string.sub (body, to + 2, to + 4)) -- always 00a101 so far
    assert (bin2 == "00a101")
    local date = hex (string.sub (body, to + 5, to + 8)) -- not yet decoded (seems to be a number of seconds, but the epoch keeps
                                                         -- incrementing in multiples of 128 seconds)
    local rest = to + 9
    local from, to, alias = string.find (body, "\003\168\001(%Z*)", to + 3)
    local bin3, bin4
    if from then
      bin3 = hex (string.sub (body, rest, from - 1))
      bin4 = hex (string.sub (body, to + 2, -1))
    else
      bin3 = hex (string.sub (body, rest, -1))
    end
    local _, _, dir = string.find (bin3, "00cd010(.)")
    if not dir then
      _, _, dir = string.find (bin4, "00cd010(.)")
    end
    assert (dir)
    if dir and bit.band (dir, 4) == 0 then
      dir = "out"
    else
      dir = "in"
    end
    assert (type == "00c9010103d001" or -- control message
            type == "00c9010203d001") -- ordinary message
    rec[seq] = {
      seq = seq,
      name = name,
      mess = mess,
      alias = alias,
      date = date,
      bin0 = bin0,
      bin3 = bin3,
      bin4 = bin4,
      bin5 = bin5,
      dir = dir,
    }
    table.setn (rec, table.getn(rec) + 1)
    print (rec[seq])
  end
  print (table.getn (rec) .. " records")
end


-- Command-line options
options = {
}

-- Main routine
getopt.processArgs ()
if table.getn (arg) == 0 then
  getopt.dieWithUsage ()
end
io.processFiles (main)


-- Changelog

--   0.1  04aug04 Program started
--   0.11 06sep04 Refined interpretation of message files
--   0.12 08sep04 Now have direction of message

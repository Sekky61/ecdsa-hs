-- FLP projekt 1 2022/23 - Elliptic curve cryptography
-- Author: xmajer21 - Michal Majer
-- Date: 2023-03-18

module EC (module ECParse, module ECTypes, module EC) where

import Data.List (genericReplicate)
import Data.Maybe (fromJust, fromMaybe)
import ECParse
import ECTypes
import Numeric (showHex)

-- Curve form: y^2 = x^3 + ax + b
-- Use integer arithmetic modulo n or p everywhere
-- Source: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication

-- todo key should be printed using Show, but I need curve parameter to get the length of the key
-- instance Show Key where
printKey :: Curve -> Key -> String
printKey curve (Key privk (PublicKey pk)) = "Key {\nd: " ++ dHex ++ "\nQ: " ++ encodePoint pk curveOrder ++ "\n}"
  where
    dHex = numToHexString privk
    curveOrder = p curve

-- Encode point in uncompressed form
-- n is the order of field
-- TODO maybe using wrong padding length
-- Source: https://secg.org/sec1-v2.pdf##subsubsection.2.3.3
encodePoint :: Point -> Integer -> String
encodePoint (Point xi yi) ni = "0x04" ++ convx ++ convy
  where
    nDouble = fromIntegral ni :: Double
    bitLenFloat = logBase 2 nDouble
    byteLenFloat = bitLenFloat / 8
    byteLenInt = ceiling byteLenFloat
    hexLen = byteLenInt * 2
    convx = padHex (showHex (abs xi) "") hexLen
    convy = padHex (showHex (abs yi) "") hexLen

-- Prepend zeros to a string until it is of length n
padHex :: String -> Integer -> String
padHex str num = genericReplicate (num - strLen) '0' ++ str
  where
    strLen = fromIntegral (length str)

-- Elliptic curve operations

-- Extended Euclidean algorithm to find the modular inverse
extendedEuclidean :: Integer -> Integer -> (Integer, Integer, Integer)
extendedEuclidean ai 0 = (ai, 1, 0)
extendedEuclidean ai bi = (gcdi, ti, si - qi * ti)
  where
    (qi, ri) = divMod ai bi
    (gcdi, si, ti) = extendedEuclidean bi ri

-- return number x such that num*x = 1 (mod nModule)
modularInverse :: Integer -> Integer -> Maybe Integer
modularInverse num nModule
  | gcdi /= 1 = Nothing -- a and n are not relatively prime, so no modular inverse exists
  | otherwise = Just si
  where
    (gcdi, si, _) = extendedEuclidean num nModule

negatePoint :: Point -> Point
negatePoint (Point xp yp) = Point xp (- yp)

-- P + Q = R
addPoint :: Curve -> Point -> Point -> Point
addPoint curve (Point xp yp) (Point xq yq) = if pointsAreSame then doublePoint curve (Point xp yp) else result
  where
    pointsAreSame = xp == xq && yp == yq
    divisor = modularInverse (xq - xp) (p curve)
    divisorUnwrapped = fromJust divisor
    lambda = ((yq - yp) * divisorUnwrapped) `mod` p curve -- slope
    lambda2 = lambda * lambda :: Integer
    xr = (lambda2 - xp - xq) `mod` p curve :: Integer
    yr = (lambda * (xp - xr) - yp) `mod` p curve
    addedPoint = Point xr yr
    result = modPoint curve addedPoint

-- P + P = 2P
doublePoint :: Curve -> Point -> Point
doublePoint curve (Point xi yi) = result
  where
    divisor = modularInverse (2 * yi) (p curve)
    divisorUnwrapped = fromJust divisor
    xi2 = xi * xi :: Integer
    lambda = ((3 * xi2 + a curve) * divisorUnwrapped) `mod` p curve :: Integer -- slope
    lambda2 = lambda * lambda :: Integer
    xr = (lambda2 - 2 * xi) `mod` p curve
    yr = (lambda * (xi - xr) - yi) `mod` p curve
    doubledPoint = Point xr yr
    result = modPoint curve doubledPoint

-- Does a mod p on the point
-- Always in the range [0...p-1]
modPoint :: Curve -> Point -> Point
modPoint curve (Point px py) = Point (mod px (p curve)) (mod py (p curve))

-- TODO
-- addPointChecked
-- https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Point_doubling

-- k: scalar
-- P: point
-- Does apply mod p
-- result: kP
pointMultiplyScalar :: Curve -> Integer -> Point -> Point
pointMultiplyScalar curve k point = case k of
  0 -> Point 0 0
  1 -> point
  _ | even k -> pointMultiplyScalar curve (k `div` 2) doubledPoint
    where
      doubledPoint = doublePoint curve point
  _ -> addPoint curve multipliedPoint point
    where
      multipliedPoint = pointMultiplyScalar curve (k - 1) point

-- Generate a key pair
-- rand: random integer
generateKeyPair :: Curve -> Integer -> Key
generateKeyPair curve rand = Key dVal (PublicKey qVal)
  where
    dVal = rand `mod` p curve -- random integer in the range [0...n-1]
    qVal = pointMultiplyScalar curve dVal (g curve)

-- Sign a hash with a private key
-- rand: random integer
signHash :: Curve -> Key -> Hash -> Integer -> Either SignatureError Signature
signHash curve (Key privD _) (Hash hash) rand = case k_inv of
  Nothing -> Left NoModularInverse
  Just _ -> Right (Signature rVal sVal)
  where
    k = rand `mod` n curve -- random number k in the range [1..n-1]
    rVal = x $ pointMultiplyScalar curve k (g curve) -- x coordinate of point R, R = kG
    k_inv = modularInverse k (n curve)
    sVal = case k_inv of
      Nothing -> 0
      Just inv_k -> (inv_k * (hash + rVal * privD)) `mod` n curve

-- Verify a signature
-- True if signature was created with the private key
verifySignature :: Curve -> Hash -> Signature -> PublicKey -> Bool
verifySignature curve (Hash hash) (Signature rVal sVal) (PublicKey pk) = case s_inv_res of
  Nothing -> False
  Just _ -> r' == rVal
  where
    nCurve = n curve
    s_inv_res = modularInverse sVal nCurve
    s_inv = fromMaybe 0 s_inv_res
    c1 = (hash * s_inv) `mod` nCurve
    c2 = (rVal * s_inv) `mod` nCurve
    r' = x $ addPoint curve (pointMultiplyScalar curve c1 (g curve)) (pointMultiplyScalar curve c2 pk) -- x coordinate of point R', R' = (h * s1) * G + (r * s1) * pubKey

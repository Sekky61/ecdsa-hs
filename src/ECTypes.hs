-- FLP projekt 1 2022/23 - Elliptic curve cryptography
-- Author: xmajer21 - Michal Majer
-- Date: 2023-03-18

module ECTypes
  ( Point (..),
    Curve (..),
    Key (..),
    Signature (..),
    Hash (..),
    SignatureError (..),
    PublicKey (..),
    numToHexString,
  )
where

import Numeric (showHex)

data Point = Point
  { x :: Integer,
    y :: Integer
  }
  deriving (Show, Eq, Read)

newtype PublicKey = PublicKey Point deriving (Eq, Read)

type PrivateKey = Integer

-- Elliptic curve
-- Form: y^2 = x^3 + ax + b
data Curve = Curve
  { p :: Integer, -- modulo used in calculations
    a :: Integer, -- coefficient
    b :: Integer, -- coefficient
    g :: Point, -- Generator point
    n :: Integer, -- Order, used to verify signature
    h :: Integer
  }
  deriving (Eq, Read)

data Key = Key
  { d :: PrivateKey, -- Private key
    q :: PublicKey -- Public key
  }
  deriving (Eq, Read)

-- Signature, result of signing a message
data Signature = Signature
  { r :: Integer, -- Reference value used for verifying signature
    s :: Integer
  }
  deriving (Eq, Read)

data SignatureError
  = NoModularInverse
  deriving (Show, Eq, Read)

newtype Hash = Hash Integer
  deriving (Show, Eq, Read)

-- Printing

numToHexString :: Integer -> String
numToHexString num = "0x" ++ showHex num ""

instance Show Key where
  show key = "Key {\nd: " ++ dHex ++ "\nQ: x: " ++ qXHex ++ "(" ++ show qX ++ ")" ++ "\n   y: " ++ qYHex ++ "(" ++ show qY ++ ")" ++ "\n}"
    where
      qPoint :: Point
      qPoint = case q key of
        (PublicKey pk) -> pk
      qX = x qPoint
      qXHex = numToHexString qX
      qY = y qPoint
      qYHex = numToHexString qY
      dHex = numToHexString (d key)

instance Show Curve where
  show curve = "Curve {\np: " ++ numToHexString (p curve) ++ "\na: " ++ show (a curve) ++ "\nb: " ++ show (b curve) ++ "\ng: " ++ gPointString ++ "\nn: " ++ numToHexString (n curve) ++ "\nh: " ++ show (h curve) ++ "\n}"
    where
      gPointString = "Point {\n   x: " ++ numToHexString (x (g curve)) ++ "\n   y: " ++ numToHexString (y (g curve)) ++ "\n}"

-- TODO pad with zeros??
instance Show Signature where
  show (Signature ri si) = "Signature {\nr: " ++ numToHexString ri ++ "\ns: " ++ numToHexString si ++ "\n}"

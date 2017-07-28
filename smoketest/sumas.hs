main = do
     str <- getLine
     print $ sum $ map read $ words str

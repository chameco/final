module Final.Utility.Exception where

import Control.Exception.Safe

throwLeft :: (Exception e, MonadThrow m) => Either e a -> m a
throwLeft (Left e) = throwM e 
throwLeft (Right x) = pure x

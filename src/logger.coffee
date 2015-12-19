
# Simple multi-level logging interface that writes to STDERR so we can use
# STDOUT redirect

module.exports = do ->
  _levels = ['debug', 'info', 'warn', 'error']
  _level  = 2
  logger  = {
    setLevel : (l) -> _level = _levels.indexOf(l)
  }
  for level, index in _levels then do (level, index) ->
    logger[level] = -> if _level <= index then console.error.apply(console, arguments)
  return logger

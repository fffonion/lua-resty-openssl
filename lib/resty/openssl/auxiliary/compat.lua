local nkeys

do
  local pok, perr = pcall(require, "table.nkeys")
  if pok then
    nkeys = perr
  else
    nkeys = function(tbl)
      local cnt = 0
      for _ in pairs(tbl) do
          cnt = cnt + 1
      end
      return cnt
    end
  end
end

return {
  nkeys = nkeys,
}
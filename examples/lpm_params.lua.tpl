require "gatekeeper/staticlib"
require "gatekeeper/policylib"

local dyc = staticlib.c.get_dy_conf()

if dyc.gt == nil then
	return "Gatekeeper: failed to run as Grantor server\n"
end

local function get_lpm_params()
	local lcore = policylib.c.gt_lcore_id()
	local num_rules, num_tbl8s = {{lpm_params_function}}({{lpm_table}})
	return lcore .. ":" .. num_rules .. "," .. num_tbl8s .. "\n"
end

dylib.update_gt_lua_states_incrementally(dyc.gt, get_lpm_params, false)

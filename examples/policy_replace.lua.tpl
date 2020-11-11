{{lpm_table}} = nil
collectgarbage()

{{lpm_table}} = {{lpm_table_constructor}}({{params.num_rules}}, {{params.num_tbl8s}})

local function update_lpm_tables()
{%- for entry in ipv4.insert %}
	add_{{entry.kind}}_v4("{{entry.range}}", {{entry.class}})
{%- endfor %}

{%- for entry in ipv6.insert %}
	add_{{entry.kind}}_v6("{{entry.range}}", {{entry.class}})
{%- endfor %}
end

local dyc = staticlib.c.get_dy_conf()
dylib.update_gt_lua_states_incrementally(dyc.gt, update_lpm_tables, false)

-- Place this file in usr/share/heka/lua_decoders/ and run the heka config file
local l = require 'lpeg'

l.locale(l)
local num = (l.digit^1 * "." * l.digit^1) / tonumber 
local name = l.upper^1*l.P("_")^-1* l.upper^0
local type = l.P("type=")*l.Cg(name,"Type")
local timestamp = l.P("msg=audit(")*l.Cg(num,"Timestamp")
local serial = l.P(":")*l.Cg(l.digit^1/tonumber,"serialnum") --Taking a integer for now

local space = l.space^0
local fieldname = l.C(l.alpha^1* (l.alnum + "-" + "_")^0)
local quoted = '"' * l.Cs(  (l.P'\\"' / '"' + (l.P(1) - '"'))^0  ) * '"'
local single_quoted = "'" * l.Cs(  (l.P"\\'" / "'" + (l.P(1) - "'") )^0  )*"'"

local numeric = l.C(l.digit^1 * #l.space^1) / tonumber
local unquoted = l.C(l.alnum^1+ l.R"!~"^1)
local fieldvalue =   quoted +single_quoted + numeric + unquoted
local sep = space
local pair = l.Cg(fieldname * "=" * fieldvalue) * sep^-1
local text = l.Cg( (1-pair)^0,"message" )*sep^-1
local tab = l.P("):")* space*(text)*l.Cg( l.Cf(l.Ct("") * pair^0, rawset),"Fields")

grammar = l.Ct(type*l.space^-1*timestamp*serial*tab)

local payload_keep = read_config("payload_keep")

local msg_type = read_config("type")

local msg = {
    Type = nil,
    Payload = nil,
	Fields = nil,
    Timestamp = nil,
}
require "os"

function process_message()
	
  	local data = read_message("Payload")  
  		
	msg = grammar:match(data)

    if not msg then
        return -1
    end

    if payload_keep then
        msg.Payload = data
    end
	local t = msg.Timestamp
	
	msg.Timestamp = os.date("%Y-%m-%d %H:%M:%S",t)

	msg.Fields["type"] = msg.Type --Event Type
	msg.Fields["serialNum"] = msg.serialnum
	--For special cases like type = AVC
	if msg.message ~= "" then
		msg.Fields["msgdata"] = msg.message
	else
		msg.message = nil
	end
	
	msg.serialnum = nil
	msg.Type = msg_type
		
    if not pcall(inject_message, msg) then return -1 end
    
    return 0
end

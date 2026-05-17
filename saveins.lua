--SAVEINSTANCE
--start bytecode_decompiler.exe first

local DECOMPILER_URL = "http://127.0.0.1:31337/decompile"
local SAVEINSTANCE_URL = "https://raw.githubusercontent.com/topzurdo/romansalates/refs/heads/main/saveinstance.lua"

local HttpService = game:GetService("HttpService")
local httprequest = request or httprequest or (syn and syn.request) or (http and http.request)

local function encodeBytecode(bytecode)
	if crypt and crypt.base64encode then
		return crypt.base64encode(bytecode)
	end
	if base64 and base64.encode then
		return base64.encode(bytecode)
	end
	error("base64 encode not available")
end

function bytecodeDecompile(script)
	local bytecode = getscriptbytecode(script)
	if not bytecode or bytecode == "" then
		return "-- failed to read bytecode"
	end
	if not httprequest then
		return "-- httprequest not available"
	end
	local res = httprequest({
		Url = DECOMPILER_URL,
		Method = "POST",
		Headers = { ["Content-Type"] = "application/json" },
		Body = HttpService:JSONEncode({
			bytecode = encodeBytecode(bytecode),
			mode = "decompile",
		}),
	})
	if type(res) ~= "table" or not res.Body then
		return "-- bytecode_decompiler not reachable (run bytecode_decompiler.exe)"
	end
	local body = HttpService:JSONDecode(res.Body)
	if body.ok then
		return body.code
	end
	return "-- decompile error: " .. tostring(body.error or "unknown")
end

getgenv().decompile = bytecodeDecompile

local synSI = loadstring(game:HttpGet(SAVEINSTANCE_URL, true), "saveinstance")()
getgenv().synsaveinstance = synSI
getgenv().saveinstance = synSI
task.wait(3)
local synsaveinstance = loadstring(game:HttpGet(SAVEINSTANCE_URL, true), "saveinstance")()
local Options = {
	IsolateLocalPlayer = true,
	IsolateLocalPlayerCharacter = true,
	IsolateStarterPlayer = true,
	IgnoreDefaultPlayerScripts = false,
	IsolatePlayers = true,
}
synsaveinstance(Options)

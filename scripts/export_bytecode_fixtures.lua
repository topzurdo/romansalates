--[[
  Export quality Luau bytecode fixtures (.bin) for bytecode_decompiler tests.

  Requirements: getscriptbytecode + writefile (+ makefolder optional).

  Usage (executor console, inside a game):
    loadstring(readfile("bytecodeveryop/scripts/export_bytecode_fixtures.lua"))()

  Output: bytecodeveryop/fixtures/export_<timestamp>/
    fixture_01.bin … fixture_N.bin  (short names)
    manifest.json                   (full Roblox paths + scores)

  Copy corpus_*.bin or fixture_*.bin to:
    crates/bytecode_decompiler/tests/fixtures/
]]

local CONFIG = {
	MIN_COUNT = 10,
	MAX_COUNT = 20,
	OUTPUT_ROOT = "bytecodeveryop/fixtures",

	-- Hard size limits (bytes).
	MIN_BYTECODE_SIZE = 1800,
	MAX_BYTECODE_SIZE = 256 * 1024,

	-- Only client-replicated script types.
	SCRIPT_CLASSES = {
		LocalScript = true,
		ModuleScript = true,
	},

	SKIP_ROOTS = {
		"CoreGui",
		"CorePackages",
		"RobloxReplicatedStorage",
		"RobloxGui",
		"Chat",
		"TextChatService",
	},

	-- FullName substring → skip (UI clones, templates, per-player GUI, item spam).
	SKIP_PATH_PATTERNS = {
		"PlayerGui",
		"RowTemplate",
		"ColumnTemplate",
		"Template%.",
		"%.Template",
		"HiddenFrames",
		"InventoryItems",
		"FrameworkDependencies%.%x%x%x%x%x%x%x%x",
		"%.properties$",
		"RandomItemsPolicy",
		"ViewportFrame",
		"ScrollingFrame%.Row",
		"StarterPlayerScripts", -- duplicate of Players.*.PlayerScripts
	},

	-- Script.Name → skip.
	SKIP_NAMES = {
		properties = true,
		Policy = true,
		Animate = true,
		Health = true,
	},

	-- Prefer these roots when scoring.
	PREFERRED_ROOTS = {
		"ReplicatedStorage",
		"StarterGui",
		"StarterPlayer",
		"StarterPack",
	},

	PREFERRED_NAME_KEYWORDS = {
		Framework = 25,
		Cmdr = 20,
		Loader = 20,
		Handler = 10,
		Controller = 10,
		Service = 10,
		Module = 8,
		Client = 8,
	},

	-- Max exports sharing the same parent folder (avoid 5x TroopBuilder clones).
	MAX_PER_PARENT = 1,
}

local getBytecode = getscriptbytecode or getsbc
if not getBytecode then
	error("[export] getscriptbytecode is not available in this executor")
end
if not writefile then
	error("[export] writefile is not available in this executor")
end

local HttpService = game:GetService("HttpService")

local function log(...)
	print("[bytecode-export]", ...)
end

local function warnMsg(...)
	warn("[bytecode-export]", ...)
end

local function ensureFolder(path)
	if makefolder and isfolder then
		if not isfolder(path) then
			local ok, err = pcall(makefolder, path)
			if not ok then
				error("[export] makefolder failed for " .. path .. ": " .. tostring(err))
			end
		end
	end
end

local function matchesAnyPattern(fullName, patterns)
	for _, pat in ipairs(patterns) do
		if fullName:find(pat) then
			return true, pat
		end
	end
	return false
end

local function isUnderSkipRoot(instance)
	local p = instance
	while p and p ~= game do
		for _, name in ipairs(CONFIG.SKIP_ROOTS) do
			if p.Name == name then
				return true, name
			end
		end
		p = p.Parent
	end
	return false
end

local function parentKey(script)
	local p = script.Parent
	if not p then
		return "?"
	end
	return p:GetFullName()
end

local function scoreScript(script, bytecodeSize)
	local full = script:GetFullName()
	local score = 0

	if script.ClassName == "ModuleScript" then
		score = score + 15
	end

	for _, root in ipairs(CONFIG.PREFERRED_ROOTS) do
		if full:find("^game%." .. root) or full:find("." .. root .. ".", 1, true) then
			score = score + 20
			break
		end
	end

	if full:find("PlayerScripts", 1, true) and not full:find("PlayerGui", 1, true) then
		score = score + 18
	end

	if full:find("Players%.", 1, true) then
		score = score - 25
	end

	for keyword, pts in pairs(CONFIG.PREFERRED_NAME_KEYWORDS) do
		if full:find(keyword, 1, true) or script.Name:find(keyword, 1, true) then
			score = score + pts
		end
	end

	-- Larger scripts tend to be more interesting for decompiler tests.
	score = score + math.min(bytecodeSize / 400, 25)

	-- Penalize ultra-deep nesting (usually cloned UI leaf scripts).
	local depth = select(2, full:gsub("%.", ""))
	if depth > 8 then
		score = score - (depth - 8) * 4
	end

	return score
end

local function collectCandidates()
	local list = {}
	for _, inst in ipairs(game:GetDescendants()) do
		if not CONFIG.SCRIPT_CLASSES[inst.ClassName] then
			continue
		end
		if CONFIG.SKIP_NAMES[inst.Name] then
			continue
		end
		local skipRoot, rootName = isUnderSkipRoot(inst)
		if skipRoot then
			continue
		end
		local full = inst:GetFullName()
		local badPath, pat = matchesAnyPattern(full, CONFIG.SKIP_PATH_PATTERNS)
		if badPath then
			continue
		end
		table.insert(list, inst)
	end
	return list
end

local function readBytecode(script)
	local ok, bytecode = pcall(getBytecode, script)
	if not ok or type(bytecode) ~= "string" then
		return nil, ok and "not a string" or tostring(bytecode)
	end
	if #bytecode < CONFIG.MIN_BYTECODE_SIZE then
		return nil, "too small (" .. #bytecode .. " bytes, min " .. CONFIG.MIN_BYTECODE_SIZE .. ")"
	end
	if #bytecode > CONFIG.MAX_BYTECODE_SIZE then
		return nil, "too large (" .. #bytecode .. " bytes)"
	end
	return bytecode
end

local function buildRankedList(scripts)
	local ranked = {}
	for _, script in ipairs(scripts) do
		local bytecode, err = readBytecode(script)
		if bytecode then
			table.insert(ranked, {
				script = script,
				bytecode = bytecode,
				size = #bytecode,
				score = scoreScript(script, #bytecode),
				parent = parentKey(script),
				fullName = script:GetFullName(),
				className = script.ClassName,
			})
		end
	end
	table.sort(ranked, function(a, b)
		if a.score ~= b.score then
			return a.score > b.score
		end
		return a.size > b.size
	end)
	return ranked
end

local function bytecodeHash(data)
	-- FNV-1a 32-bit (enough to dedupe PlayerScripts vs StarterPlayer twins)
	local hash = 2166136261
	for i = 1, #data do
		hash = bit32.bxor(hash, string.byte(data, i))
		hash = (hash * 16777619) % 4294967296
	end
	return string.format("%08x", hash)
end

local function pickDiverse(ranked, want)
	local picked = {}
	local parentCounts = {}
	local seenHash = {}

	for _, entry in ipairs(ranked) do
		if #picked >= want then
			break
		end
		local pk = entry.parent
		local count = parentCounts[pk] or 0
		if count >= CONFIG.MAX_PER_PARENT then
			continue
		end
		local hash = bytecodeHash(entry.bytecode)
		if seenHash[hash] then
			continue
		end
		seenHash[hash] = true
		parentCounts[pk] = count + 1
		table.insert(picked, entry)
	end

	return picked
end

local function run()
	math.randomseed(os.time())

	local candidates = collectCandidates()
	log("scanned", #candidates, "scripts after filters")

	if #candidates == 0 then
		error("[export] no eligible scripts — try a game with ReplicatedStorage/StarterGui modules")
	end

	local ranked = buildRankedList(candidates)
	log("readable", #ranked, "scripts pass size limits")

	if #ranked == 0 then
		error("[export] no readable bytecode — raise MIN_BYTECODE_SIZE or join another game")
	end

	local want = math.random(CONFIG.MIN_COUNT, CONFIG.MAX_COUNT)
	if want > #ranked then
		want = #ranked
	end

	local picked = pickDiverse(ranked, want)

	local timestamp = os.date("%Y%m%d_%H%M%S")
	local outDir = CONFIG.OUTPUT_ROOT .. "/export_" .. timestamp
	ensureFolder(CONFIG.OUTPUT_ROOT)
	ensureFolder(outDir)

	local manifest = {
		exportedAt = timestamp,
		game = game.Name,
		placeId = game.PlaceId,
		requested = want,
		candidates = #candidates,
		readable = #ranked,
		exported = {},
		skippedSamples = {},
	}

	for i, entry in ipairs(picked) do
		local fileName = string.format("fixture_%02d.bin", i)
		local path = outDir .. "/" .. fileName
		local writeOk, writeErr = pcall(writefile, path, entry.bytecode)
		if not writeOk then
			warnMsg("writefile failed", entry.fullName, writeErr)
		else
			table.insert(manifest.exported, {
				file = fileName,
				fullName = entry.fullName,
				className = entry.className,
				bytes = entry.size,
				score = entry.score,
				parent = entry.parent,
			})
			log(string.format("OK [%d/%d] score=%d size=%d %s -> %s", i, want, entry.score, entry.size, entry.fullName, fileName))
		end
	end

	-- Log a few rejected high-count examples for debugging.
	for i = 1, math.min(5, #ranked) do
		local e = ranked[i]
		if e.score < (picked[1] and picked[1].score or 0) then
			table.insert(manifest.skippedSamples, {
				fullName = e.fullName,
				score = e.score,
				bytes = e.size,
				reason = "lower rank",
			})
		end
	end

	local manifestPath = outDir .. "/manifest.json"
	pcall(writefile, manifestPath, HttpService:JSONEncode(manifest))

	log("---")
	log("exported", #manifest.exported, "fixtures to", outDir)
	log("manifest:", manifestPath)
	log("rename good ones to corpus_<name>.bin in crates/bytecode_decompiler/tests/fixtures/")
	log("verify: bytecode_decompiler.exe --diag path\\to\\fixture_01.bin")

	return manifest
end

return run()

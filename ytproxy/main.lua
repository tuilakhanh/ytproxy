local mp = require 'mp'
local mpopts = require("mp.options")

local opts = {
    port = "3003",
    appname = "ytproxy",
    cert_filename = "cert.pem",
    key_filename = "key.pem",
}

mpopts.read_options(opts, "ytproxy")

local function is_windows()
    return mp.get_property_native("platform") == "windows"
end

local function buildProxyArgs()
    local scriptDir = mp.get_script_directory()
    local args = {
      scriptDir .. "/" .. (is_windows() and opts.appname .. ".exe" or opts.appname),
      "-c", scriptDir .. "/" .. opts.cert_filename,
      "-k", scriptDir .. "/" .. opts.key_filename,
      "-p", opts.port,
    }
    return args
end

local function run_proxy()
    local args = buildProxyArgs()
    mp.command_native_async({
        name = "subprocess",
        capture_stdout = false,
        capture_stderr = false,
        playback_only = false,
        args = args,
    })
end

local function init()
    local url = mp.get_property("stream-open-filename", "")

    -- check for youtube link
    if url:find("^https:") == nil or url:find("youtu") == nil then
        return
    end

    local proxy = mp.get_property("http-proxy")
    if proxy and proxy ~= "" and proxy ~= "http://127.0.0.1:" .. opts.port then
        return
    end

    run_proxy()

    mp.set_property("http-proxy", "http://127.0.0.1:" .. opts.port)
    mp.set_property("tls-verify", "yes")
    mp.set_property("tls-ca-file", mp.get_script_directory() .. "/cert.pem")
end

local function restart_proxy(event)
    if event.prefix == "ffmpeg" then
        if string.find(event.text, "^tls: The specified session has been invalidated for some reason.") then
            run_proxy()
        end
    end
end

mp.enable_messages("info")
mp.register_event("log-message", restart_proxy)
mp.register_event("start-file", init)
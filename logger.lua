local reader = require('read14a')
local cmds = require('commands')


getmetatable('').__call = function(self, start, stop, step)
    local t = {}
    for i = start, stop or start, step or 1 do
        t[#t + 1] = self:sub(i, i)
    end
    return table.concat(t)
end


function readBlock(block, keyType, key)
    local keyTypeIDs = {A=0, B=1}
    local response, err = reader.sendToDevice(Command:new{
        cmd = cmds.CMD_MIFARE_READBL,
        arg1 = block,
        arg2 = keyTypeIDs[keyType:upper()],
        data = key
    })
    if err then
        return nil, err
    elseif not response then
        return nil, 'Timeout'
    end

    local command = Command.parse(response)
    if command.arg1 == 0 then
        return nil, 'Auth failed'
    end
    return command.data:sub(1, 16 * 2)  -- 16 bytes in one block
end


function readEmulator(block)
    local response, err = reader.sendToDevice(Command:new{
        cmd = cmds.CMD_MIFARE_EML_MEMGET,
        arg1 = block,
        arg2 = 1  -- blocks count, we only read one block
    })
    if err then
        return nil, err
    elseif not response then
        return nil, 'Timeout'
    end

    local command = Command.parse(response)
    return command.data:sub(1, 16 * 2)  -- 16 bytes in one block
end


function setDebugLevel(n)
    return reader.sendToDevice(Command:new{
        cmd = cmds.CMD_MIFARE_SET_DBGMODE,
        arg1 = n
    })
end


local function main()
    -- os.execute('clear')
    local info = assert(reader.waitFor14443a())
    setDebugLevel(0)
    core.console('hf mf nested o 63 A FFFFFFFFFFFF 6 A t')

    local block = {}
    block[7] = assert(readEmulator(7))
    local key = block[7](1, 12)
    block[6] = assert(readBlock(6, 'A', key))
    block[5] = assert(readBlock(5, 'A', key))

    info.serialNo = block[5](14, 28, 2)
    info.balance  = block[6](2, 10, 2)
    info.checksum = block[6](11, 14)

    print()
    print('Tag Type:',  info.name)
    print('Unique ID:', info.uid)
    print('Serial No:', info.serialNo)
    print('Balance:',   info.balance..'-'..info.checksum)

    local logFile = assert(io.open('balance.log', 'a'))
    local logEntry = {
        os.date('%Y-%m-%d\t%X'),
        info.serialNo,
        info.balance,
        info.checksum
    }
    logFile:write(table.concat(logEntry, '\t'), '\n')
    logFile:close()
end


while not pcall(main) do end

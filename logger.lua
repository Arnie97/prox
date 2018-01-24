local reader = require('read14a')
local cmds = require('commands')


local function keyTypeID(key_type)
    id = {A=0, B=1}
    return id[key_type:upper()]
end


local function readBlock(block, key_type, key)
    response, err = reader.sendToDevice(Command:new{
        cmd = cmds.CMD_MIFARE_READBL,
        arg1 = block,
        arg2 = keyTypeID(key_type),
        arg3 = 0,
        data = key
    })
    if err then
        return nil, err
    elseif not response then
        return nil, 'Timeout'
    end

    command = Command.parse(response)
    if command.arg1 == 0 then
        return nil, 'Auth failed'
    end
    return command.data
end


local function main(args)
    -- os.execute('clear')
    info, err = reader.waitFor14443a()
    if err then
        print(err)
        return
    end
    print('Type:', info.name)
    print('UID:',  info.uid)
    block, err = readBlock(6, 'A', 'afff416c2daf')
    if err then
        print(err)
        return
    end
    print('Data:', block:sub(1, 16))
end


main(args)

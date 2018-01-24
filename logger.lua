local reader = require('read14a')
local cmds = require('commands')


local function readBlock(block, keyType, key)
    keyTypeIDs = {A=0, B=1}
    response, err = reader.sendToDevice(Command:new{
        cmd = cmds.CMD_MIFARE_READBL,
        arg1 = block,
        arg2 = keyTypeIDs[keyType:upper()],
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
    return command.data:sub(1, 16 * 2)  -- 16 bytes in one block
end


local function main(args)
    -- os.execute('clear')
    info = assert(reader.waitFor14443a())
    key = 'afff416c2daf'

    print('Type:', info.name)
    print('UID:',  info.uid)

    block = assert(readBlock(5, 'A', key))
    print('Card:', block:sub(14, 28))

    block = assert(readBlock(6, 'A', key))
    print('Data:', block:sub(1, 16))
end


main(args)

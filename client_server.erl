-module(client_server).
-export([start/0, client/2, server/2]).

start() ->
    {PublicKey, PrivateKey} = crypto:generate_key(rsa, {2048,65537}),

    ServerPid = spawn(?MODULE, server, [[],PrivateKey]),
    lists:foreach(fun(_) ->
                        spawn(?MODULE, client, [ServerPid, PublicKey])
                    end, lists:seq(1, 5)),
    ok.

client(ServerPid, ServerPublicKey) ->
    {PublicKey, PrivateKey} = crypto:generate_key(rsa, {2048,65537}),
    EncryptedMessage = encrypt("Hello, server!", ServerPublicKey),
    ServerPid ! {self(), EncryptedMessage, PublicKey},
    receive
        {server, EncryptedResponse} ->
            DecryptedResponse = decrypt(EncryptedResponse, PrivateKey),
            Message = binary_to_list(DecryptedResponse),
            io:format("Received from server: ~s ~p ~n", [Message,self()])
    end.

server(ClientPids,PrivateKey) ->
    receive
        {ClientPid, EncryptedMessage, ClientPublicKey} ->
            DecryptedMessage = decrypt(EncryptedMessage, PrivateKey),
            Message = binary_to_list(DecryptedMessage),
            io:format("Received from client ~p: ~s~n",[ClientPid,Message]),
            EncryptedResponse = encrypt("Hello, client!", ClientPublicKey),
            ClientPid ! {server, EncryptedResponse},
            server(ClientPids ++ [ClientPid],PrivateKey)

    end.
encrypt(Message, PublicKey) ->
     CipherText = crypto:public_encrypt(rsa, list_to_binary(Message), PublicKey, rsa_pkcs1_padding),
    CipherText.

decrypt(CipherText, PrivateKey) ->
     DecryptedMessage = crypto:private_decrypt(rsa, CipherText, PrivateKey, rsa_pkcs1_padding),
    DecryptedMessage.

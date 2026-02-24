-module(mesh_demo).
-export([run/0]).

run() ->
    AliceId = mesh_aegis:new_identity(),
    BobId = mesh_aegis:new_identity(),
    BobOpk = mesh_aegis:new_one_time_prekey(),

    {Hello, Alice0} = mesh_aegis:init_initiator(AliceId, maps:get(pub, BobId), maps:get(pub, BobOpk)),
    Bob0 = mesh_aegis:init_responder(BobId, BobOpk, Hello),

    io:format("Handshake complete.~n", []),

    {Packet1, Alice1} = mesh_aegis:encrypt(Alice0, <<"secret message #1">>),

    Tampered = Packet1#{cipher => <<0, 1, 2, 3>>},
    case mesh_aegis:decrypt(Bob0, Tampered) of
        {error, authentication_failed, _} ->
            io:format("Tampering attack blocked (GCM auth fail).~n", []);
        Other ->
            io:format("Unexpected tamper result: ~p~n", [Other])
    end,

    {ok, Plain1, Bob1} = mesh_aegis:decrypt(Bob0, Packet1),
    io:format("Bob decrypted: ~p~n", [Plain1]),

    case mesh_aegis:decrypt(Bob1, Packet1) of
        {error, replay_detected, _} ->
            io:format("Replay attack blocked.~n", []);
        Other2 ->
            io:format("Unexpected replay result: ~p~n", [Other2])
    end,

    {Packet2, Bob2} = mesh_aegis:encrypt(Bob1, <<"reply from Bob">>),
    {ok, Plain2, _Alice2} = mesh_aegis:decrypt(Alice1, Packet2),
    io:format("Alice decrypted: ~p~n", [Plain2]),

    io:format("State advanced (Bob send ctr=~p).~n", [element(5, Bob2)]),
    ok.

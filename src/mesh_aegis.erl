-module(mesh_aegis).

-export([
    new_identity/0,
    new_one_time_prekey/0,
    init_initiator/3,
    init_responder/3,
    encrypt/2,
    decrypt/2
]).

-record(state, {
    role,
    send_ck,
    recv_ck,
    send_ctr = 0,
    recv_ctr = -1
}).

%%%===================================================================
%%% API
%%%===================================================================

new_identity() ->
    {Pub, Priv} = crypto:generate_key(ecdh, x25519),
    #{pub => Pub, priv => Priv}.

new_one_time_prekey() ->
    {Pub, Priv} = crypto:generate_key(ecdh, x25519),
    #{pub => Pub, priv => Priv}.

%% Alice side
init_initiator(AliceId, BobIdPub, BobOneTimePub) ->
    {EkPub, EkPriv} = crypto:generate_key(ecdh, x25519),

    Dh1 = dh(EkPriv, BobIdPub),
    Dh2 = dh(maps:get(priv, AliceId), BobOneTimePub),
    Dh3 = dh(EkPriv, BobOneTimePub),

    Salt = crypto:strong_rand_bytes(32),
    Ikm = <<Dh1/binary, Dh2/binary, Dh3/binary>>,
    Root = hkdf(Salt, Ikm, <<"aegis-root">>, 32),

    SendCk = hkdf(<<0:256>>, Root, <<"init->resp">>, 32),
    RecvCk = hkdf(<<0:256>>, Root, <<"resp->init">>, 32),

    Hello = #{
        salt => Salt,
        ek_pub => EkPub,
        alice_id_pub => maps:get(pub, AliceId)
    },

    State = #state{role = initiator, send_ck = SendCk, recv_ck = RecvCk},
    {Hello, State}.

%% Bob side
init_responder(BobId, BobOneTime, Hello) ->
    Salt = maps:get(salt, Hello),
    AliceEkPub = maps:get(ek_pub, Hello),
    AliceIdPub = maps:get(alice_id_pub, Hello),

    Dh1 = dh(maps:get(priv, BobId), AliceEkPub),
    Dh2 = dh(maps:get(priv, BobOneTime), AliceIdPub),
    Dh3 = dh(maps:get(priv, BobOneTime), AliceEkPub),

    Ikm = <<Dh1/binary, Dh2/binary, Dh3/binary>>,
    Root = hkdf(Salt, Ikm, <<"aegis-root">>, 32),

    SendCk = hkdf(<<0:256>>, Root, <<"resp->init">>, 32),
    RecvCk = hkdf(<<0:256>>, Root, <<"init->resp">>, 32),

    #state{role = responder, send_ck = SendCk, recv_ck = RecvCk}.

encrypt(State = #state{send_ck = Ck, send_ctr = Ctr0}, Plaintext) when is_binary(Plaintext) ->
    Ctr = Ctr0 + 1,
    {MsgKey, NextCk} = derive_message_key(Ck, Ctr),
    Nonce = crypto:strong_rand_bytes(12),
    Header = term_to_binary(#{ctr => Ctr, nonce => Nonce}),
    {Cipher, Tag} = crypto:crypto_one_time_aead(aes_256_gcm, MsgKey, Nonce, Plaintext, Header, true),

    Packet = #{header => Header, cipher => Cipher, tag => Tag},
    {Packet, State#state{send_ck = NextCk, send_ctr = Ctr}}.

decrypt(State = #state{recv_ck = Ck, recv_ctr = LastCtr}, Packet) ->
    Header = maps:get(header, Packet),
    Cipher = maps:get(cipher, Packet),
    Tag = maps:get(tag, Packet),
    #{ctr := Ctr, nonce := Nonce} = binary_to_term(Header),

    case Ctr =< LastCtr of
        true ->
            {error, replay_detected, State};
        false ->
            {MsgKey, NextCk} = derive_message_key(Ck, Ctr),
            case crypto:crypto_one_time_aead(aes_256_gcm, MsgKey, Nonce, Cipher, Header, Tag, false) of
                Error when Error =:= error; Error =:= <<>> ->
                    {error, authentication_failed, State};
                Plain when is_binary(Plain) ->
                    {ok, Plain, State#state{recv_ck = NextCk, recv_ctr = Ctr}}
            end
    end.

%%%===================================================================
%%% Internals
%%%===================================================================

dh(Priv, Pub) ->
    crypto:compute_key(ecdh, Pub, Priv, x25519).

derive_message_key(Ck, Ctr) ->
    CtrBin = <<Ctr:64/unsigned-big>>,
    MsgKey = hmac_sha256(Ck, <<"msg", CtrBin/binary>>),
    NextCk = hmac_sha256(Ck, <<"next">>),
    {MsgKey, NextCk}.

hkdf(Salt, Ikm, Info, Len) ->
    Prk = hmac_sha256(Salt, Ikm),
    hkdf_expand(Prk, Info, Len).

hkdf_expand(Prk, Info, Len) ->
    N = (Len + 31) div 32,
    Full = hkdf_expand_blocks(Prk, Info, N, 1, <<>>, <<>>),
    binary:part(Full, 0, Len).

hkdf_expand_blocks(_Prk, _Info, N, I, _Prev, Acc) when I > N ->
    Acc;
hkdf_expand_blocks(Prk, Info, N, I, Prev, Acc) ->
    Block = hmac_sha256(Prk, <<Prev/binary, Info/binary, I:8>>),
    hkdf_expand_blocks(Prk, Info, N, I + 1, Block, <<Acc/binary, Block/binary>>).

hmac_sha256(Key, Data) ->
    crypto:mac(hmac, sha256, Key, Data).

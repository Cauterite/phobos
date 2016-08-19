/**
MurmurHash3 implementation.

 *
 * This module conforms to the APIs defined in $(D std.digest.digest). To understand the
 * differences between the template and the OOP API, see $(D std.digest.digest).
 *
 * This module publicly imports $(D std.digest.digest) and can be used as a stand-alone
 * module.
 *
 * License:   $(WEB ????, ?????????).
 *
 * Authors:   ?
 *
 * References:
 *      $(LINK2 https://en.wikipedia.org/wiki/MurmurHash, Wikipedia on MurmurHash)
 *
 * Source: $(PHOBOSSRC std/digest/_murmur.d)
 *
 * Macros:
 * WIKI = Phobos/???????????
 *
 * CTFE:
 * CTFE is supported
 */
/*
 * Copyright (c)
 * ???????
 * Distributed ?????????
 */
module std.digest.murmur;

public import std.digest.digest;
import core.internal.hash : murmur3BytesHash = bytesHash;

version(unittest)
    import std.exception;


///
unittest
{
    //Template API
    import std.digest.murmur;

    ubyte[4] hash = murmur3Of("The quick brown fox jumps over the lazy dog");
    assert(murmurHexString(hash) == "31532FCF");

    //Feeding data
    ubyte[1024] data;
    Murmur3 murmur;
    murmur.put(data[]);
    murmur.start(); //Start again
    murmur.put(data[]);
    hash = murmur.finish();
}

unittest
{
    //Template API in CTFE
    import std.digest.murmur;

    enum hash = murmur3Of("The quick brown fox jumps over the lazy dog");
    static assert(murmurHexString(hash) == "31532FCF");
}

///
unittest
{
    //OOP API
    import std.digest.murmur;

    auto murmur = new Murmur3Digest();
    ubyte[] hash = murmur.digest("The quick brown fox jumps over the lazy dog");
    assert(murmurHexString(hash) == "31532FCF");

    //Feeding data
    ubyte[1024] data;
    murmur.put(data[]);
    murmur.reset(); //Start again
    murmur.put(data[]);
    hash = murmur.finish();
}

///
unittest
{
    //OOP API in CTFE
    import std.digest.murmur;

    enum hash = ({
        auto murmur = new Murmur3Digest();
        murmur.put(cast(ubyte[]) "The quick brown fox jumps over the lazy dog");
        return murmur.finish();
    })();
    static assert(murmurHexString(hash) == "31532FCF");
}

/**
 * Template API Murmur3 implementation.
 * See $(D std.digest.digest) for differences between template and OOP API.
 */
struct Murmur3
{
    private:
        // Murmur3 is designed to hash a stream of uints, not a stream of bytes,
        // so we must buffer the excess bytes.
        uint seed;
        ubyte[4] tail;
        size_t tailCount;

        // buffer should never be full after `put` returns
        invariant {assert(tailCount < tail.length);}

        @property uint state() const @safe pure nothrow
        {
            // combine `seed` with any buffered bytes
            if (tailCount)
            {
                auto x = tail[0 .. tailCount];
                // cast because bytesHash() only generates 32-bit values,
                // even though it returns size_t.
                return cast(uint) murmur3BytesHash(x.ptr, x.length, seed);
            }

            // if the buffer is empty, `seed` is our state
            return seed;
        }

    public:
        /**
         * Use this to feed the digest with data.
         * Also implements the $(XREF_PACK range,primitives,isOutputRange)
         * interface for $(D ubyte) and $(D const(ubyte)[]).
         */
        void put(scope const(ubyte)[] data...) @trusted pure nothrow
        {
            foreach (x; data)
            {
                tail[tailCount++] = x;

                // empty the buffer if it's full
                if (tailCount == tail.length)
                {
                    seed = state;
                    tail[] = 0;
                    tailCount = 0;
                }
            }
        }
        ///
        unittest
        {
            Murmur3 dig;
            dig.put(cast(ubyte)0); //single ubyte
            dig.put(cast(ubyte)0, cast(ubyte)0); //variadic
            ubyte[10] buf;
            dig.put(buf); //buffer
        }

        /**
         * Used to initialize the Murmur3 digest.
         *
         * Note:
         * For this Murmur3 Digest implementation calling start after default construction
         * is not necessary. Calling start is only necessary to reset the Digest.
         *
         * Generic code which deals with different Digest types should always call start though.
         */
        void start() @safe pure nothrow @nogc
        {
            this = Murmur3.init;
        }
        ///
        unittest
        {
            Murmur3 digest;
            //digest.start(); //Not necessary
            digest.put(0);
        }

        /**
         * Returns the finished Murmur3 hash. This also calls $(LREF start) to
         * reset the internal state.
         */
        ubyte[4] finish() @safe pure nothrow
        {
            auto tmp = peek();
            start();
            return tmp;
        }
        ///
        unittest
        {
            //Simple example
            Murmur3 hash;
            hash.put(cast(ubyte)0);
            ubyte[4] result = hash.finish();
        }

        /**
         * Works like $(D finish) but does not reset the internal state, so it's possible
         * to continue putting data into this Murmur3 after a call to peek.
         */
        ubyte[4] peek() const @trusted pure nothrow
        {
            uint x = state; // need an lvalue for reinterpret-cast
            if (__ctfe)
            {
                // ctfe does not support int to byte[] casting
                ubyte[4] ret;
                foreach (i; 0 .. ret.length)
                    ret[i] = cast(ubyte) (x >> (i * 8));
                return ret;
            }
            return *(cast(ubyte[4]*) &x);
        }
}

///
unittest
{
    //Simple example, hashing a string using murmur3Of helper function
    ubyte[4] hash = murmur3Of("abc");
    //Let's get a hash string
    assert(murmurHexString(hash) == "B3DD93FA");
}

///
unittest
{
    //Using the basic API
    Murmur3 hash;
    ubyte[1024] data;
    //Initialize data here...
    hash.put(data);
    ubyte[4] result = hash.finish();
}

///
unittest
{
    //Let's use the template features:
    //Note: When passing a Murmur3 to a function, it must be passed by reference!
    void doSomething(T)(ref T hash) if(isDigest!T)
    {
      hash.put(cast(ubyte)0);
    }
    Murmur3 murmur;
    murmur.start();
    doSomething(murmur);
    assert(murmurHexString(murmur.finish()) == "514E28B7");
}

unittest
{
    assert(isDigest!Murmur3);
}

unittest
{
    ubyte[4] digest;

    Murmur3 murmur;
    murmur.put(cast(ubyte[])"abcdefghijklmnopqrstuvwxyz");
    assert(murmur.peek() == cast(ubyte[])x"e941388d");
    murmur.start();
    murmur.put(cast(ubyte[])"");
    assert(murmur.finish() == cast(ubyte[])x"00000000");

    digest = murmur3Of("");
    assert(digest == cast(ubyte[])x"00000000");

    assert(murmurHexString(murmur3Of("The quick brown fox jumps over the lazy dog")) == "31532FCF");

    digest = murmur3Of("a");
    assert(digest == cast(ubyte[])x"b269253c");

    digest = murmur3Of("abc");
    assert(digest == cast(ubyte[])x"fa93ddb3");

    digest = murmur3Of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert(digest == cast(ubyte[])x"cda4f519");

    digest = murmur3Of("message digest");
    assert(digest == cast(ubyte[])x"2991a262");

    digest = murmur3Of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    assert(digest == cast(ubyte[])x"65c70a0d");

    digest = murmur3Of("1234567890123456789012345678901234567890"~
                    "1234567890123456789012345678901234567890");
    assert(digest == cast(ubyte[])x"fc0eb5c0");

    assert(murmurHexString(cast(ubyte[4])x"c3fcd3d7") == "D7D3FCC3");
}

/**
 * This is a convenience alias for $(XREF_PACK digest,digest,digest) using the
 * Murmur3 implementation.
 *
 * Params:
 *      data = $(D InputRange) of $(D ElementType) implicitly convertible to
 *             $(D ubyte), $(D ubyte[]) or $(D ubyte[num]) or one or more arrays
 *             of any type.
 *
 * Returns:
 *      Murmur3 of data
 */
//simple alias doesn't work here, hope this gets inlined...
ubyte[4] murmur3Of(T...)(T data)
{
    return digest!(Murmur3, T)(data);
}

///
unittest
{
    ubyte[] data = [4,5,7,25];
    assert(data.murmur3Of == [9, 171, 148, 188]);

    import std.utf : byChar;
    assert("hello"d.byChar.murmur3Of == [214, 175, 136, 213]);

    ubyte[4] hash = "abc".murmur3Of();
    assert(hash == digest!Murmur3("ab", "c"));

    import std.range : iota;
    enum ubyte S = 5, F = 66;
    assert(iota(S, F).murmur3Of == [74, 60, 66, 201]);
}

/**
 * This is a convenience alias for $(XREF_PACK digest,digest,toHexString)
 * producing the usual Murmur3 string output.
 */
public alias murmurHexString = toHexString!(Order.decreasing);
///ditto
public alias murmurHexString = toHexString!(Order.decreasing, 16);


/**
 * OOP API Murmur3 implementation.
 * See $(D std.digest.digest) for differences between template and OOP API.
 *
 * This is an alias for $(D $(XREF_PACK digest,digest,WrapperDigest)!Murmur3), see
 * there for more information.
 */
alias Murmur3Digest = WrapperDigest!Murmur3;

///
unittest
{
    //Simple example, hashing a string using Digest.digest helper function
    auto murmur = new Murmur3Digest();
    ubyte[] hash = murmur.digest("abc");
    //Let's get a hash string
    assert(murmurHexString(hash) == "B3DD93FA");
}

///
unittest
{
     //Let's use the OOP features:
    void test(Digest dig)
    {
      dig.put(cast(ubyte)0);
    }
    auto murmur = new Murmur3Digest();
    test(murmur);

    //Let's use a custom buffer:
    ubyte[4] buf;
    ubyte[] result = murmur.finish(buf[]);
    assert(murmurHexString(result) == "514E28B7");
}

///
unittest
{
    //Simple example
    auto hash = new Murmur3Digest();
    hash.put(cast(ubyte)0);
    ubyte[] result = hash.finish();
}

///
unittest
{
    //using a supplied buffer
    ubyte[4] buf;
    auto hash = new Murmur3Digest();
    hash.put(cast(ubyte)0);
    ubyte[] result = hash.finish(buf[]);
    //The result is now in result (and in buf. If you pass a buffer which is bigger than
    //necessary, result will have the correct length, but buf will still have it's original
    //length)
}

void print(ubyte[] xs) {
	assert(xs.length == 4);
	import s = std.stdio;
	s.writefln(`%02x%02x%02x%02x`, xs[0],xs[1],xs[2],xs[3]);
};
//    import std.stdio;
//    .writeln;

unittest
{
    import std.range;

    auto murmur = new Murmur3Digest();

    murmur.put(cast(ubyte[])"abcdefghijklmnopqrstuvwxyz");
    assert(murmur.peek() == cast(ubyte[])x"e941388d");
    murmur.reset();
    murmur.put(cast(ubyte[])"");
    assert(murmur.finish() == cast(ubyte[])x"00000000");

    murmur.put(cast(ubyte[])"abcdefghijklmnopqrstuvwxyz");
    ubyte[20] result;
    auto result2 = murmur.finish(result[]);
    assert(result[0 .. 4] == result2 && result2 == cast(ubyte[])x"e941388d");

    debug
        assertThrown!Error(murmur.finish(result[0 .. 3]));

    assert(murmur.length == 4);

    assert(murmur.digest("") == cast(ubyte[])x"00000000");

    assert(murmur.digest("a") == cast(ubyte[])x"b269253c");

    assert(murmur.digest("abc") == cast(ubyte[])x"fa93ddb3");

    assert(murmur.digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
           == cast(ubyte[])x"cda4f519");

    assert(murmur.digest("message digest") == cast(ubyte[])x"2991a262");

    assert(murmur.digest("abcdefghijklmnopqrstuvwxyz")
           == cast(ubyte[])x"e941388d");

    assert(murmur.digest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
           == cast(ubyte[])x"65c70a0d");

    assert(murmur.digest("1234567890123456789012345678901234567890",
                                   "1234567890123456789012345678901234567890")
           == cast(ubyte[])x"fc0eb5c0");

    ubyte[] onemilliona = new ubyte[1000000];
    onemilliona[] = 'a';
    auto digest = murmur3Of(onemilliona);
    assert(digest == cast(ubyte[])x"9fd16389");

    auto oneMillionRange = repeat!ubyte(cast(ubyte)'a', 1000000);
    digest = murmur3Of(oneMillionRange);
    assert(digest == cast(ubyte[])x"9fd16389");
}

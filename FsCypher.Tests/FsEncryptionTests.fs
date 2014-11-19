namespace FsCypher.Tests

open NUnit.Framework
open FsUnit
open FsCypher.AesEncryption

module ``FsEncryption Tests`` =
    
    module ``AES Encryption`` =
        
        [<Test>]
        let ``Roundtrip should return original text`` () =
            let algo = Aes.Create ()
            let original = "hello"
            let encrypted = aesEncrypt original algo.Key algo.IV
            aesDecrypt encrypted algo.Key algo.IV |> should equal original
           
         
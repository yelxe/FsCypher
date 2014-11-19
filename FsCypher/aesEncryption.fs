namespace FsCypher

open System.Security.Cryptography
open System.IO

module AesEncryption =
    
    [<AbstractClass>]
    type Aes =  
        class
            inherit SymmetricAlgorithm
        end
    
    let aesEncrypt (plainText:string) (key:byte[]) (iv:byte[]) =
        
        let algo = Aes.Create ()
        algo.Key <- key
        algo.IV <- iv

        let encryptor = algo.CreateEncryptor(algo.Key, algo.IV)
        
        use msEncrypt = new MemoryStream()
        (
            use csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write)
            use swEncrypt = new StreamWriter(csEncrypt)
            swEncrypt.Write(plainText)
        )
        let cypherText = msEncrypt.ToArray ()

        algo.Clear |> ignore

        cypherText

    let aesDecrypt (cypherText:byte[]) (key:byte[]) (iv:byte[]) =
        
        let algo = Aes.Create ()
        algo.Key <- key
        algo.IV <- iv

        let decryptor = algo.CreateDecryptor(algo.Key, algo.IV)
        
        let msDecrypt = new MemoryStream(cypherText)
        let csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read)
        let srDecrypt = new StreamReader(csDecrypt)

        let plainText = srDecrypt.ReadToEnd ()

        srDecrypt.Close |> ignore
        csDecrypt.Close |> ignore
        msDecrypt.Close |> ignore

        algo.Clear |> ignore

        plainText

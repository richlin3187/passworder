const string IV = "1234567890";
Console.WriteLine("Enter a file to encrypt.");
var fileLocation = Console.ReadLine();
var fileContents = System.IO.File.ReadAllText(fileLocation!);

Console.WriteLine("Enter a password.");
var password = Console.ReadLine();

var cryptor = new Cryptor();
var encryptedText = cryptor.Encrypt(fileContents, password!, IV);

Console.WriteLine(encryptedText);

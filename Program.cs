using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Transactions;
using Passworder;
public class Program
{
    private enum CurrentAction
    {
        Undecided = 0,
        Encrypt = 1,
        Decrypt = 2,
        Exit = 3,
    } 

    public static void Main()
    {
        var currentAction = CurrentAction.Undecided;
        while (currentAction != CurrentAction.Exit)
        {
            Write("Main Menu:");
            Write("1. Encrypt a file.");
            Write("2. Decrypt a file.");
            Write("3. Exit program.");
            var selection = Console.ReadLine();
            if (Enum.TryParse<CurrentAction>(selection, true, out currentAction))
            {
                switch (currentAction)
                {
                    case CurrentAction.Encrypt:
                        EncryptAction();
                        break;
                    case CurrentAction.Decrypt:
                        DecryptAction();
                        break;
                    default:
                        break;
                }
            }
            else 
            {
                Write("Invalid selection");
                currentAction = CurrentAction.Undecided;
            }
        }
        
    }

    private static void EncryptAction()
    {
        Write("Enter a file to encrypt.");
        var fileLocation = Console.ReadLine();
        var fileContents = File.ReadAllText(fileLocation!);

        Write("Enter a password.");
        var password = Console.ReadLine();

        Write("Enter a password hint.");
        var hint = Console.ReadLine();

        var cryptor = new Cryptor();
        var encryptedValue = cryptor.Encrypt(fileContents, password!, hint!);

        var encryptedContents = JsonSerializer.Serialize(encryptedValue);
        File.WriteAllText(fileLocation!, encryptedContents);
        Write($"File encrypted at {fileLocation!}. Press any key to continue.");
        Console.ReadKey();
    }

    private static void DecryptAction()
    {
        Write("Enter a file to decrypt.");
        var fileLocation = Console.ReadLine();
        var fileContents = File.ReadAllText(fileLocation!);
        var encryptedValue = JsonSerializer.Deserialize<EncryptedValue>(fileContents);

        Write("Enter the password to decrypt this file:");
        var password = Console.ReadLine();

        var cryptor = new Cryptor();
        var decryptedValue = cryptor.Decrypt(encryptedValue!, password!);
        Write(decryptedValue);
    }
    
    private static void Write(string message)
    {
        Console.WriteLine(message);
    }
}

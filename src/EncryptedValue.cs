namespace Passworder;

internal record EncryptedValue
{
    public EncryptedValue(string cypherText, string hint, string nonce)
    {
        this.CypherText = cypherText;
        this.Hint = hint;
        this.Nonce = nonce;
    }

    public string CypherText { get; set; }

    public string Hint { get; set; }

    public string Nonce { get; set; }
}
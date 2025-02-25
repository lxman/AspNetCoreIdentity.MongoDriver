namespace AspNetCoreIdentity.MongoDriver.Models;

internal class TwoFactorRecoveryCode
{
    public string Code { get; set; }

    public bool Redeemed { get; set; }
}
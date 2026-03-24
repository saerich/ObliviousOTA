namespace ObliviousOTA.Models.Request;

internal record KTVRequest(string Username, string Alpha1, string Alpha2, string Beta1, string Beta2, string N1, string N2, string RWDU1, string RWDU2, string DeviceKey, string FWHash, ulong RealBlocks, int AbsorbedBlocks, string SK);
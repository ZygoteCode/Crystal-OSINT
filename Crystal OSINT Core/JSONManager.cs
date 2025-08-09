using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

public class JSONManager
{
    public static string BeautifyJSON(string json)
    {
        try
        {
            return JToken.Parse(json).ToString(Formatting.Indented);
        }
        catch
        {
            return json;
        }
    }

    public static string MinifyJSON(string json)
    {
        try
        {
            return JToken.Parse(json).ToString(Formatting.None);
        }
        catch
        {
            return json;
        }
    }
}
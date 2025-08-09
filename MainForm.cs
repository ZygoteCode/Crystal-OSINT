using Crystal_OSINT.Properties;
using MetroSuite;
using Microsoft.VisualBasic;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

public partial class MainForm : MetroForm
{
    [DllImport("psapi.dll")]
    private static extern int EmptyWorkingSet(IntPtr hwProc);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetProcessWorkingSetSize(IntPtr process, UIntPtr minimumWorkingSetSize, UIntPtr maximumWorkingSetSize);

    private OSINTDogManager _osintDogManager;

    public MainForm()
    {
        InitializeComponent();
        InitializeCrystalOSINT();
        guna2ComboBox1.SelectedIndex = 0;
    }

    public List<string> FindString(string filePath, string toBeFound, bool facebook = false)
    {
        toBeFound = toBeFound.ToLower();
        List<string> found = new List<string>();
        int bufferSize = 16 * 1024 * 1024;

        using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            using (StreamReader reader = new StreamReader(fs, Encoding.UTF8, true, bufferSize))
            {
                string line;

                while ((line = reader.ReadLine()) != null)
                {
                    if (facebook)
                    {
                        line = line.Replace(":", " ");
                    }

                    if (line.ToLower().Contains(toBeFound))
                    {
                        found.Add(line);
                    }
                }
            }
        }

        return found;
    }

    private string DomainWhoIs(string domain)
    {
        try
        {
            var request1 = (HttpWebRequest)WebRequest.Create($"https://www.whois.com/whois/{domain}");

            request1.Proxy = null;
            request1.UseDefaultCredentials = false;
            request1.AllowAutoRedirect = false;
            request1.Timeout = 70000;

            var field1 = typeof(HttpWebRequest).GetField("_HttpRequestHeaders", BindingFlags.Instance | BindingFlags.NonPublic);
            request1.Method = "GET";

            var headers1 = new CustomWebHeaderCollection(new Dictionary<string, string>
            {
                ["Host"] = "www.whois.com",
                ["Connection"] = "keep-alive",
                ["Upgrade-Insecure-Requests"] = "1",
                ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
                ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                ["Sec-Fetch-Site"] = "same-origin",
                ["Sec-Fetch-Mode"] = "navigate",
                ["Sec-Fetch-User"] = "?1",
                ["Sec-Fetch-Dest"] = "document",
                ["sec-ch-ua-mobile"] = "?0",
                ["sec-ch-ua-platform"] = "\"Windows\"",
                ["Accept-Language"] = "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
                ["Cookie"] = "cookieconsent_prompt=1",
            });

            field1.SetValue(request1, headers1);

            var response1 = request1.GetResponse();
            string content1 = Encoding.UTF8.GetString(ReadFully(response1.GetResponseStream()));
            string[] splitted = Strings.Split(content1, "http://web-whois.nic.it");
            content1 = splitted[1];
            splitted = Strings.Split(content1, "Domain: ");
            content1 = "Domain: " + splitted[1];
            splitted = Strings.Split(content1, "</pre></div></div>");
            content1 = splitted[0];

            return content1;
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    private byte[] ReadFully(Stream input)
    {
        using (MemoryStream ms = new MemoryStream())
        {
            input.CopyTo(ms);
            return ms.ToArray();
        }
    }

    public void InitializeCrystalOSINT()
    {
        DoubleBuffered = true;
        CheckForIllegalCrossThreadCalls = false;

        _osintDogManager = new OSINTDogManager();
        Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.RealTime;

        ServicePointManager.DefaultConnectionLimit = int.MaxValue;
        ServicePointManager.MaxServicePoints = int.MaxValue;

        Thread clearRamThread = new Thread(ClearRAM);
        clearRamThread.Priority = ThreadPriority.Highest;
        clearRamThread.Start();
    }

    public void ClearRAM()
    {
        while (true)
        {
            Thread.Sleep(750);
            EmptyWorkingSet(Process.GetCurrentProcess().Handle);
            GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
            GC.Collect(GC.MaxGeneration);
            GC.WaitForPendingFinalizers();
            SetProcessWorkingSetSize(Process.GetCurrentProcess().Handle, (UIntPtr)0xFFFFFFFF, (UIntPtr)0xFFFFFFFF);
        }
    }

    private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
    {
        Process.GetCurrentProcess().Kill();
    }

    private void guna2Button3_Click(object sender, EventArgs e)
    {
        try
        {
            string username = guna2TextBox1.Text;

            new Thread(() =>
            {
                string result = "[";
                result += _osintDogManager.AkulaSearch(username, "username") + ",";
                result += _osintDogManager.BreachBaseSearch(username, "username") + ",";
                result += _osintDogManager.HackCheckSearch(username, "username") + ",";
                result += _osintDogManager.Inf0SecSearch(username, "username") + ",";
                result += _osintDogManager.Inf0SecSearch(username, "leaks") + ",";
                result += _osintDogManager.IntelVaultSearch(username, "username") + ",";
                result += _osintDogManager.LeakCheckSearch(username, "username") + ",";
                result += _osintDogManager.LeakSightSearch(username, "username") + ",";
                result += _osintDogManager.SnusbaseSearch(username, "username");
                result += "]";
                result = result.Replace("Lookup made by https://osintdog.com", "Lookup made by Crystal OSINT");

                guna2TextBox2.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox2.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button4_Click(object sender, EventArgs e)
    {
        try
        {
            new Thread(() =>
            {
                string result = JSONManager.BeautifyJSON(guna2TextBox2.Text);

                guna2TextBox2.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox2.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button5_Click(object sender, EventArgs e)
    {
        try
        {
            new Thread(() =>
            {
                string result = JSONManager.MinifyJSON(guna2TextBox2.Text);

                guna2TextBox2.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox2.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button6_Click(object sender, EventArgs e)
    {
        try
        {
            if (saveFileDialog1.ShowDialog().Equals(DialogResult.OK))
            {
                File.WriteAllText(saveFileDialog1.FileName, guna2TextBox2.Text);
            }
        }
        catch
        {

        }
    }

    private void guna2Button10_Click(object sender, EventArgs e)
    {
        try
        {
            string email = guna2TextBox4.Text;

            new Thread(() =>
            {
                string result = "[";
                result += _osintDogManager.SnusbaseSearch(email, "email") + ",";
                result += _osintDogManager.LeakCheckSearch(email, "email") + ",";
                result += _osintDogManager.HackCheckSearch(email, "email") + ",";
                result += _osintDogManager.BreachBaseSearch(email, "email") + ",";
                result += _osintDogManager.IntelVaultSearch(email, "email") + ",";
                result += _osintDogManager.Inf0SecSearch(email, "leaks") + ",";
                result += _osintDogManager.AkulaSearch(email, "email") + ",";
                result += _osintDogManager.OathNetGHuntEmailSearch(email) + ",";
                result += _osintDogManager.OathNetHoleleEmailSearch(email) + ",";
                result += _osintDogManager.SEONEmailSearch(email);
                result += "]";
                result = result.Replace("Lookup made by https://osintdog.com", "Lookup made by Crystal OSINT");

                guna2TextBox3.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox3.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button9_Click(object sender, EventArgs e)
    {
        try
        {
            new Thread(() =>
            {
                string result = JSONManager.BeautifyJSON(guna2TextBox3.Text);

                guna2TextBox3.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox3.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button8_Click(object sender, EventArgs e)
    {
        try
        {
            new Thread(() =>
            {
                string result = JSONManager.MinifyJSON(guna2TextBox3.Text);

                guna2TextBox3.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox3.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button7_Click(object sender, EventArgs e)
    {
        try
        {
            if (saveFileDialog1.ShowDialog().Equals(DialogResult.OK))
            {
                File.WriteAllText(saveFileDialog1.FileName, guna2TextBox3.Text);
            }
        }
        catch
        {

        }
    }

    private void guna2Button14_Click(object sender, EventArgs e)
    {
        try
        {
            string domain = guna2TextBox6.Text;

            new Thread(() =>
            {
                string result = "[";
                result += _osintDogManager.SnusbaseSearch(domain, "_domain") + ",";
                result += _osintDogManager.LeakCheckSearch(domain, "domain") + ",";
                result += _osintDogManager.Inf0SecSearch(domain, "domain") + ",";
                result += _osintDogManager.AkulaSearch(domain, "domain") + ",";
                result += _osintDogManager.HackCheckSearch(domain, "domain");
                result += "]";
                result = result.Replace("Lookup made by https://osintdog.com", "Lookup made by Crystal OSINT");

                guna2TextBox5.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox5.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button13_Click(object sender, EventArgs e)
    {
        try
        {
            new Thread(() =>
            {
                string result = JSONManager.BeautifyJSON(guna2TextBox5.Text);

                guna2TextBox5.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox5.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button12_Click(object sender, EventArgs e)
    {
        try
        {
            new Thread(() =>
            {
                string result = JSONManager.MinifyJSON(guna2TextBox5.Text);

                guna2TextBox5.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox5.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button11_Click(object sender, EventArgs e)
    {
        try
        {
            if (saveFileDialog1.ShowDialog().Equals(DialogResult.OK))
            {
                File.WriteAllText(saveFileDialog1.FileName, guna2TextBox5.Text);
            }
        }
        catch
        {

        }
    }

    private void guna2Button18_Click(object sender, EventArgs e)
    {
        try
        {
            string ip = guna2TextBox8.Text;

            new Thread(() =>
            {
                string result = "[";
                result += _osintDogManager.HackCheckSearch(ip, "ip_address") + ",";
                result += _osintDogManager.Inf0SecSearch(ip, "leaks") + ",";
                result += _osintDogManager.SnusbaseSearch(ip, "lastip");
                result += "]";
                result = result.Replace("Lookup made by https://osintdog.com", "Lookup made by Crystal OSINT");

                guna2TextBox7.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox7.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button17_Click(object sender, EventArgs e)
    {
        try
        {
            new Thread(() =>
            {
                string result = JSONManager.BeautifyJSON(guna2TextBox7.Text);

                guna2TextBox7.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox7.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button16_Click(object sender, EventArgs e)
    {
        try
        {
            new Thread(() =>
            {
                string result = JSONManager.MinifyJSON(guna2TextBox7.Text);

                guna2TextBox7.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox7.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button15_Click(object sender, EventArgs e)
    {
        try
        {
            if (saveFileDialog1.ShowDialog().Equals(DialogResult.OK))
            {
                File.WriteAllText(saveFileDialog1.FileName, guna2TextBox7.Text);
            }
        }
        catch
        {

        }
    }

    private void guna2Button22_Click(object sender, EventArgs e)
    {
        try
        {
            string phone = guna2TextBox10.Text;

            new Thread(() =>
            {
                string result = "[";
                result += _osintDogManager.LeakCheckSearch(phone, "phone") + ",";
                result += _osintDogManager.HackCheckSearch(phone, "phone_number") + ",";
                result += _osintDogManager.Inf0SecSearch(phone, "leaks") + ",";
                result += _osintDogManager.SEONPhoneSearch(phone);
                result += "]";
                result = result.Replace("Lookup made by https://osintdog.com", "Lookup made by Crystal OSINT");

                guna2TextBox9.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox9.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button21_Click(object sender, EventArgs e)
    {
        try
        {
            new Thread(() =>
            {
                string result = JSONManager.BeautifyJSON(guna2TextBox9.Text);

                guna2TextBox9.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox9.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button20_Click(object sender, EventArgs e)
    {
        try
        {
            new Thread(() =>
            {
                string result = JSONManager.MinifyJSON(guna2TextBox9.Text);

                guna2TextBox9.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox9.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button19_Click(object sender, EventArgs e)
    {
        try
        {
            if (saveFileDialog1.ShowDialog().Equals(DialogResult.OK))
            {
                File.WriteAllText(saveFileDialog1.FileName, guna2TextBox9.Text);
            }
        }
        catch
        {

        }
    }

    private void guna2Button26_Click(object sender, EventArgs e)
    {
        try
        {
            string discordId = guna2TextBox12.Text;

            new Thread(() =>
            {
                string result = "[";
                result += _osintDogManager.Inf0SecSearch(discordId, "discord") + ",";
                result += _osintDogManager.Inf0SecSearch(discordId, "leaks");
                result += "]";
                result = result.Replace("Lookup made by https://osintdog.com", "Lookup made by Crystal OSINT");

                guna2TextBox11.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox11.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button25_Click(object sender, EventArgs e)
    {
        try
        {
            new Thread(() =>
            {
                string result = JSONManager.BeautifyJSON(guna2TextBox11.Text);

                guna2TextBox11.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox11.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button24_Click(object sender, EventArgs e)
    {
        try
        {
            new Thread(() =>
            {
                string result = JSONManager.MinifyJSON(guna2TextBox11.Text);

                guna2TextBox11.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox11.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button23_Click(object sender, EventArgs e)
    {
        try
        {
            if (saveFileDialog1.ShowDialog().Equals(DialogResult.OK))
            {
                File.WriteAllText(saveFileDialog1.FileName, guna2TextBox11.Text);
            }
        }
        catch
        {

        }
    }

    private void guna2Button30_Click(object sender, EventArgs e)
    {
        try
        {
            string hash = guna2TextBox14.Text;

            new Thread(() =>
            {
                string result = "[";
                result += _osintDogManager.SnusbaseSearch(hash, "domain") + ",";
                result += _osintDogManager.LeakCheckSearch(hash, "hash") + ",";
                result += _osintDogManager.HackCheckSearch(hash, "hash") + ",";
                result += _osintDogManager.Inf0SecSearch(hash, "leaks");
                result += "]";
                result = result.Replace("Lookup made by https://osintdog.com", "Lookup made by Crystal OSINT");

                guna2TextBox13.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox13.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button29_Click(object sender, EventArgs e)
    {
        try
        {
            new Thread(() =>
            {
                string result = JSONManager.BeautifyJSON(guna2TextBox13.Text);

                guna2TextBox13.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox13.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button28_Click(object sender, EventArgs e)
    {
        try
        {
            new Thread(() =>
            {
                string result = JSONManager.MinifyJSON(guna2TextBox13.Text);

                guna2TextBox13.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox13.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button27_Click(object sender, EventArgs e)
    {
        try
        {
            if (saveFileDialog1.ShowDialog().Equals(DialogResult.OK))
            {
                File.WriteAllText(saveFileDialog1.FileName, guna2TextBox13.Text);
            }
        }
        catch
        {

        }
    }

    private void guna2Button34_Click(object sender, EventArgs e)
    {
        try
        {
            string fullName = guna2TextBox16.Text;

            new Thread(() =>
            {
                string result = "[";
                result += _osintDogManager.HackCheckSearch(fullName, "full_name") + ",";
                result += _osintDogManager.Inf0SecSearch(fullName, "leaks");
                result += "]";
                result = result.Replace("Lookup made by https://osintdog.com", "Lookup made by Crystal OSINT");

                guna2TextBox15.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox15.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button33_Click(object sender, EventArgs e)
    {
        try
        {
            new Thread(() =>
            {
                string result = JSONManager.BeautifyJSON(guna2TextBox15.Text);

                guna2TextBox15.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox15.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button32_Click(object sender, EventArgs e)
    {
        try
        {
            new Thread(() =>
            {
                string result = JSONManager.MinifyJSON(guna2TextBox15.Text);

                guna2TextBox15.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox15.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void guna2Button31_Click(object sender, EventArgs e)
    {
        try
        {
            if (saveFileDialog1.ShowDialog().Equals(DialogResult.OK))
            {
                File.WriteAllText(saveFileDialog1.FileName, guna2TextBox15.Text);
            }
        }
        catch
        {

        }
    }

    private void label9_Click(object sender, EventArgs e)
    {
        string username = guna2TextBox1.Text;
        Process.Start($"https://www.snapchat.com/@{username}");
        Process.Start($"https://revolut.me/{username}");
        Process.Start($"https://www.paypal.com/paypalme/{username}");
        Process.Start($"https://x.com/{username}");
        Process.Start($"https://it.namemc.com/profile/{username}");
        Process.Start($"https://www.instagram.com/{username}");
        Process.Start($"https://t.me/{username}");
        Process.Start($"https://www.youtube.com/@{username}");
        Process.Start($"https://www.tiktok.com/@{username}");
        Process.Start($"https://api.github.com/users/{username}/events");
    }

    private void label16_Click(object sender, EventArgs e)
    {
        Process.Start("https://facecheck.id/");
    }

    private void label12_Click(object sender, EventArgs e)
    {
        Process.Start($"https://ipinfo.io/{guna2TextBox8.Text}?lookup_source=search-bar");
    }

    private void label11_Click(object sender, EventArgs e)
    {
        guna2TextBox5.Text = DomainWhoIs(guna2TextBox6.Text);
    }

    private void guna2Button36_Click(object sender, EventArgs e)
    {
        try
        {
            string searchTerm = guna2TextBox18.Text.ToLower();

            new Thread(() =>
            {
                string result = "";
                List<string> results = new List<string>();

                if (guna2ComboBox1.SelectedIndex == 0)
                {
                    foreach (string file in Directory.GetFiles(Path.GetFullPath("database\\discord")))
                    {
                        results.AddRange(FindString(file, searchTerm));
                    }
                }
                else if (guna2ComboBox1.SelectedIndex == 1)
                {
                    foreach (string file in Directory.GetFiles(Path.GetFullPath("database\\facebook")))
                    {
                        results.AddRange(FindString(file, searchTerm, true));
                    }
                }
                else if (guna2ComboBox1.SelectedIndex == 2)
                {
                    foreach (string file in Directory.GetFiles(Path.GetFullPath("database\\instagram")))
                    {
                        results.AddRange(FindString(file, searchTerm));
                    }
                }
                else if (guna2ComboBox1.SelectedIndex == 3)
                {
                    foreach (string file in Directory.GetFiles(Path.GetFullPath("database\\minecraft")))
                    {
                        FileInfo fileInfo = new FileInfo(file);
                        long limitMB = 40 * 1024 * 1024;

                        if (fileInfo.Length > limitMB)
                        {
                            continue;
                        }

                        results.AddRange(FindString(file, searchTerm));
                    }
                }
                else if (guna2ComboBox1.SelectedIndex == 4)
                {
                    foreach (string file in Directory.GetFiles(Path.GetFullPath("database\\fivem")))
                    {
                        results.AddRange(FindString(file, searchTerm));
                    }
                }
                else if (guna2ComboBox1.SelectedIndex == 5)
                {
                    foreach (string file in Directory.GetFiles(Path.GetFullPath("database\\doxbin")))
                    {
                        results.AddRange(FindString(file, searchTerm));
                    }
                }
                else if (guna2ComboBox1.SelectedIndex == 6)
                {
                    foreach (string file in Directory.GetFiles(Path.GetFullPath("database\\whatsapp")))
                    {
                        if (!file.ToLower().Contains("italy"))
                        {
                            continue;
                        }

                        results.AddRange(FindString(file, searchTerm));
                    }
                }

                foreach (string theResult in results)
                {
                    if (result == "")
                    {
                        result = theResult;
                    }
                    else
                    {
                        result += "\r\n\r\n" + theResult;
                    }
                }

                if (result == "")
                {
                    result = "No results.";
                }

                guna2TextBox17.Invoke((MethodInvoker)(() =>
                {
                    guna2TextBox17.Text = result;
                }));
            }).Start();
        }
        catch
        {

        }
    }

    private void label13_Click(object sender, EventArgs e)
    {
        Process.Start("https://sync.me/it/");
        Process.Start("https://www.truecaller.com/it-it");
    }

    private void guna2Button1_Click(object sender, EventArgs e)
    {
        try
        {
            if (saveFileDialog2.ShowDialog().Equals(DialogResult.OK))
            {
                File.WriteAllText(saveFileDialog2.FileName, guna2TextBox17.Text);
            }
        }
        catch
        {

        }
    }

    private void label1_Click(object sender, EventArgs e)
    {
        Process.Start("https://commentpicker.com/instagram-user-id.php");
    }
}
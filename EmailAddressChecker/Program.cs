using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Net;
using System.Net.Sockets;

namespace EmailAddressChecker
{
    class Program
    {
        static class Endianess
        {
            public static bool MachineArchIsLittleEndian
            {
                get { return BitConverter.IsLittleEndian; }
            }

            public static Int16 toBigEndian(Int16 value)
            {
                byte[] bytes = BitConverter.GetBytes(value);
                Array.Reverse(bytes);

                return BitConverter.ToInt16(bytes, 0);
            }

            public static Int32 toBigEndian(Int32 value)
            {
                byte[] bytes = BitConverter.GetBytes(value);
                Array.Reverse(bytes);

                return BitConverter.ToInt32(bytes, 0);
            }

            public static Int16 toLittleEndian(Int16 value)
            {
                return toBigEndian(value);
            }

            public static Int32 toLittleEndian(Int32 value)
            {
                return toBigEndian(value);
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct DNSHeader
        {
            private Int16 _transactionID;
            private Int16 _flags;
            private Int16 _questionResourceCount;
            private Int16 _answerResourceCount;
            private Int16 _authorityResourceCount;
            private Int16 _additionalResourceCount;

            private static Int16 toGetAppropriateEndianess(Int16 value)
            {
                return (Endianess.MachineArchIsLittleEndian ? Endianess.toLittleEndian(value) : value);
            }

            private static Int16 toSetAppropriateEndianess(Int16 value)
            {
                return (Endianess.MachineArchIsLittleEndian ? Endianess.toBigEndian(value) : value);
            }

            public Int16 transactionID
            {
                get
                {
                    return toGetAppropriateEndianess(this._transactionID);
                }

                set
                {
                    this._transactionID = toSetAppropriateEndianess(value);
                }
            }
            public Int16 flags
            {
                get
                {
                    return toGetAppropriateEndianess(this._flags);
                }

                set
                {
                    this._flags = toSetAppropriateEndianess(value);
                }
            }
            public Int16 questionResourceCount
            {
                get
                {
                    return toGetAppropriateEndianess(this._questionResourceCount);
                }

                set
                {
                    this._questionResourceCount = toSetAppropriateEndianess(value);
                }
            }
            public Int16 answerResourceCount
            {
                get
                {
                    return toGetAppropriateEndianess(this._answerResourceCount);
                }

                set
                {
                    this._answerResourceCount = toSetAppropriateEndianess(value);
                }
            }
            public Int16 authorityResourceCount
            {
                get
                {
                    return toGetAppropriateEndianess(this._authorityResourceCount);
                }

                set
                {
                    this._authorityResourceCount = toSetAppropriateEndianess(value);
                }
            }
            public Int16 additionalResourceCount
            {
                get
                {
                    return toGetAppropriateEndianess(this._additionalResourceCount);
                }

                set
                {
                    this._additionalResourceCount = toSetAppropriateEndianess(value);
                }
            }

            public int SizeOf()
            {
                return Marshal.SizeOf(this);
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct DNSQuestion
        {
            public enum Types : Int16
            {
                HostRecord = 0x01,
                NameServerRecord = 0x02,
                AliasRecord = 0x05,
                ReverseLookupRecord = 0x0C,
                MailExchangeRecord = 0x0F,
                ServiceRecord = 0x21,
                IncrementalZoneTransferRecord = 0xFB,
                StandardZoneTransferRecord = 0xFC,
                AllRecords = 0xFF
            }

            public const Int16 IN = 0x0001;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            private byte[] _name;
            private Int16 _type;
            private Int16 _classType;

            private static Int16 toGetAppropriateEndianess(Int16 value)
            {
                return (Endianess.MachineArchIsLittleEndian ? Endianess.toLittleEndian(value) : value);
            }

            private static Int16 toSetAppropriateEndianess(Int16 value)
            {
                return (Endianess.MachineArchIsLittleEndian ? Endianess.toBigEndian(value) : value);
            }

            public byte[] name
            {
                get { return _name; }
                set { value = _name; }
            }
            public Int16 type
            {
                get
                {
                    return toGetAppropriateEndianess(this._type);
                }

                set
                {
                    this._type = toSetAppropriateEndianess(value);
                }
            }
            public Int16 classType
            {
                get
                {
                    return toGetAppropriateEndianess(this._classType);
                }

                set
                {
                    this._classType = toSetAppropriateEndianess(value);
                }
            }

            public DNSQuestion(string name, Types type, Int16 classType = IN)
            {
                if (string.IsNullOrEmpty(name))
                    throw new ArgumentException("name argument cannot be empty or null");

                // Convert string to byte[] according to specs of DNS protocol
                int sizeNameArray = name.Length + 2 * sizeof(byte);
                this._name = new byte[sizeNameArray];

                int indexNameArray = 0;
                var arrSubstrings = name.Split(new char[] { '.' });
                foreach (var substring in arrSubstrings)
                {
                    this._name[indexNameArray++] = (byte)substring.Length;

                    foreach (var character in substring)
                    {
                        this._name[indexNameArray++] = (byte)character;
                    }
                }
                this._name[this._name.Length - 1] = 0x00;   // Terminate with null

                this._type = toSetAppropriateEndianess((Int16)type);
                this._classType = toSetAppropriateEndianess(classType);
            }

            public int SizeOf()
            {
                return (sizeof(byte) * this._name.Length +
                        Marshal.SizeOf(this._type) +
                        Marshal.SizeOf(this._classType));
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct DNSResource
        {
            public enum Types : Int16
            {
                HostRecord = 0x01,
                NameServerRecord = 0x02,
                AliasRecord = 0x05,
                ReverseLookupRecord = 0x0C,
                MailExchangeRecord = 0x0F,
                ServiceRecord = 0x21,
                IncrementalZoneTransferRecord = 0xFB,
                StandardZoneTransferRecord = 0xFC,
                AllRecords = 0xFF
            }

            public const Int16 IN = 0x0001;

            private Int16 _name;
            private Int16 _type;
            private Int16 _classType;
            private Int32 _timeToLive;
            private Int16 _dataLength;
            //private Int16 _preference;
            //private byte[] _mailExchange;

            private static Int16 toGetAppropriateEndianess(Int16 value)
            {
                return (Endianess.MachineArchIsLittleEndian ? Endianess.toBigEndian(value) : value);
            }

            private static Int32 toGetAppropriateEndianess(Int32 value)
            {
                return (Endianess.MachineArchIsLittleEndian ? Endianess.toBigEndian(value) : value);
            }

            private static Int16 toSetAppropriateEndianess(Int16 value)
            {
                return (Endianess.MachineArchIsLittleEndian ? Endianess.toLittleEndian(value) : value);
            }

            private static Int32 toSetAppropriateEndianess(Int32 value)
            {
                return (Endianess.MachineArchIsLittleEndian ? Endianess.toLittleEndian(value) : value);
            }

            public Int16 name
            {
                get
                {
                    return toGetAppropriateEndianess(this._name);
                }

                set
                {
                    this._name = toSetAppropriateEndianess(value);
                }
            }
            public Int16 type
            {
                get
                {
                    return toGetAppropriateEndianess(this._type);
                }

                set
                {
                    this._type = toSetAppropriateEndianess(value);
                }
            }
            public Int16 classType
            {
                get
                {
                    return toGetAppropriateEndianess(this._classType);
                }

                set
                {
                    this._classType = toSetAppropriateEndianess(value);
                }
            }
            public Int32 timeToLive
            {
                get
                {
                    return toGetAppropriateEndianess(this._timeToLive);
                }

                set
                {
                    this._timeToLive = toSetAppropriateEndianess(value);
                }
            }
            public Int16 dataLength
            {
                get
                {
                    return toGetAppropriateEndianess(this._dataLength);
                }

                set
                {
                    this._dataLength = toSetAppropriateEndianess(value);
                }
            }
            //public Int16 preference
            //{
            //    get
            //    {
            //        return toGetAppropriateEndianess(this._preference);
            //    }

            //    set
            //    {
            //        this._preference = toSetAppropriateEndianess(value);
            //    }
            //}
            //public byte[] mailExchange
            //{
            //    get { return this._mailExchange; }
            //    set { this._mailExchange = value; }
            //}

            public int SizeOf()
            {
                return Marshal.SizeOf(_name) +
                         Marshal.SizeOf(_type) +
                         Marshal.SizeOf(_classType) +
                         Marshal.SizeOf(_timeToLive) +
                         Marshal.SizeOf(_dataLength);// +
                                                     //Marshal.SizeOf(_preference) +
                                                     //_mailExchange.Length * sizeof(byte);
            }
        }

        class EmailVerify
        {
            public static readonly IPAddress GooglePublicDNS = IPAddress.Parse("8.8.8.8");
            private static readonly String HelloServer = "microsoft.com";
            private static readonly String QueryEmail = "support@microsoft.com";

            private IPAddress _dNSServer;
            private const int _dNSPort = 53;
            private const int _sMTPPort = 25;
            private UdpClient _dNSClient;
            private TcpClient _sMTPClient;

            public EmailVerify(IPAddress DNSServer)
            {
                _dNSServer = DNSServer;
                _dNSClient = new UdpClient(_dNSServer.ToString(), _dNSPort);
            }

            public bool AskDNS(string domain, string email)
            {
                var transactionID = (Int16)(new Random().Next(maxValue: Int16.MaxValue));

                var header = new DNSHeader
                {
                    transactionID = transactionID,
                    flags = 0x0100,                 // Just a standard query
                    questionResourceCount = 1,      // We have one question
                    answerResourceCount = 0,
                    authorityResourceCount = 0,
                    additionalResourceCount = 0
                };

                var question = new DNSQuestion(domain,
                                                DNSQuestion.Types.MailExchangeRecord);  // We want to know about mail server

                var sizeDNSQuery = header.SizeOf() + question.SizeOf();
                var arrDNSQuery = new byte[sizeDNSQuery];
                IntPtr ptrHeader = Marshal.AllocHGlobal(header.SizeOf());
                Marshal.StructureToPtr(header, ptrHeader, true);
                Marshal.Copy(ptrHeader, arrDNSQuery, 0, header.SizeOf());
                Marshal.FreeHGlobal(ptrHeader);

                // Copy char data, no need to worry about endianess for char
                question.name.CopyTo(arrDNSQuery, header.SizeOf());

                var arrQuestionType = BitConverter.GetBytes(Endianess.toBigEndian(question.type));
                var arrQuestionClassType = BitConverter.GetBytes(Endianess.toBigEndian(question.classType));

                arrQuestionType.CopyTo(arrDNSQuery, header.SizeOf() + question.name.Length * sizeof(byte));
                arrQuestionClassType.CopyTo(arrDNSQuery, header.SizeOf() + question.name.Length * sizeof(byte) + arrQuestionType.Length);

                // Send datagram
                _dNSClient.Send(arrDNSQuery, arrDNSQuery.Length * sizeof(byte));

                // Get response
                do
                {
                    var result = _dNSClient.ReceiveAsync().Result;

                    // Make sure it is from correct domain
                    if (result.RemoteEndPoint.Address.Equals(_dNSServer))
                    {
                        // Make sure packet has valid size header
                        if (result.Buffer.Length > header.SizeOf())
                        {
                            // Convert to DNSHeader
                            ptrHeader = Marshal.AllocHGlobal(header.SizeOf());
                            Marshal.Copy(result.Buffer, 0, ptrHeader, header.SizeOf());
                            header = (DNSHeader)Marshal.PtrToStructure(ptrHeader, header.GetType());
                            Marshal.FreeHGlobal(ptrHeader);

                            // Check that this is the correct transaction packet response
                            if (header.transactionID == transactionID)
                            {
                                // Check that flags has no error and there is atleast one answer
                                if (((header.flags & 0xf) != 0) || header.answerResourceCount == 0)
                                    return false;

                                // List of mail servers and their preferences
                                List<Tuple<int, string>> listMailServerAndPrefs = new List<Tuple<int, string>>();

                                // Determine the start index of Answers structure
                                int indexStartOfAnswer = arrDNSQuery.Length;

                                for (int i = 0; i < header.answerResourceCount; ++i)
                                {
                                    if ((result.Buffer[indexStartOfAnswer] & 0xC0) == 0)
                                        throw new NotImplementedException("DNS answer name must be an offset");

                                    // Convert from byte stream to answer structure
                                    IntPtr ptrAnswer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(DNSResource)));
                                    Marshal.Copy(result.Buffer, indexStartOfAnswer, ptrAnswer, Marshal.SizeOf(typeof(DNSResource)));
                                    var answer = (DNSResource)Marshal.PtrToStructure(ptrAnswer, typeof(DNSResource));
                                    Marshal.FreeHGlobal(ptrAnswer);

                                    // Increment index ahead
                                    indexStartOfAnswer += answer.SizeOf();
                                    if (indexStartOfAnswer > result.Buffer.Length)
                                        break;

                                    // Read preference no, smaller number is more preferred server
                                    if (answer.dataLength < 2)
                                        continue;

                                    Int16 preferenceMailExchangeServer = BitConverter.ToInt16(result.Buffer, indexStartOfAnswer);
                                    if (Endianess.MachineArchIsLittleEndian)
                                        preferenceMailExchangeServer = Endianess.toLittleEndian(preferenceMailExchangeServer);
                                    indexStartOfAnswer += Marshal.SizeOf(preferenceMailExchangeServer);

                                    // Read server name
                                    int sizeServerName = answer.dataLength - Marshal.SizeOf(preferenceMailExchangeServer);
                                    if (sizeServerName < 2)
                                        continue;

                                    if (indexStartOfAnswer + sizeServerName > result.Buffer.Length)
                                        break;

                                    string serverName = string.Empty;
                                    int j = indexStartOfAnswer;
                                    while (j < indexStartOfAnswer + sizeServerName - 1)
                                    {
                                        if ((result.Buffer[j] & 0xC0) != 0)
                                        {
                                            // It's an offset
                                            var offset = BitConverter.ToInt16(result.Buffer, j);
                                            if (Endianess.MachineArchIsLittleEndian)
                                                offset = Endianess.toLittleEndian(offset);
                                            offset &= 0x3F; // Remove two most significant bits
                                            j += Marshal.SizeOf(offset);

                                            // Transverse position from offset until null
                                            do
                                            {
                                                serverName += Encoding.ASCII.GetString(result.Buffer, offset + 1, result.Buffer[offset]) + '.';
                                                offset += (Int16)(result.Buffer[offset] + 1);
                                            } while (result.Buffer[offset] != 0);
                                        }
                                        else
                                        {
                                            // It's just size
                                            serverName += System.Text.Encoding.ASCII.GetString(result.Buffer, j + 1, result.Buffer[j]) + '.';
                                            j += result.Buffer[j] + 1;
                                        }
                                    }

                                    indexStartOfAnswer += answer.dataLength - Marshal.SizeOf(preferenceMailExchangeServer);

                                    if (string.IsNullOrEmpty(serverName) && serverName.Length > 2)
                                        continue;

                                    serverName = serverName.Substring(0, serverName.Length - 1);    // Remove terminating dot

                                    listMailServerAndPrefs.Add(new Tuple<int, string>((int)preferenceMailExchangeServer, serverName));
                                }

                                // Sort by preference
                                listMailServerAndPrefs = listMailServerAndPrefs.OrderBy(x => x.Item1).ToList();

                                // Connect with SMTP
                                _sMTPClient = new TcpClient();
                                _sMTPClient.ConnectAsync(listMailServerAndPrefs.First().Item2, _sMTPPort).Wait();
                                if (!_sMTPClient.Connected)
                                    throw new WebException("SMTP server refused connection");

                                var arrSMTPResponse = new byte[256];
                                var sizeSMTPResponse = _sMTPClient.Client.Receive(arrSMTPResponse);
                                var connectResponse = Encoding.ASCII.GetString(arrSMTPResponse);
                                if (!connectResponse.StartsWith("220"))
                                    throw new WebException("SMTP server refused to connect");

                                _sMTPClient.Client.Send(Encoding.ASCII.GetBytes("HELO " + HelloServer + "\r\n"));
                                sizeSMTPResponse = _sMTPClient.Client.Receive(arrSMTPResponse);
                                var heloResponse = Encoding.ASCII.GetString(arrSMTPResponse);
                                if (!heloResponse.StartsWith("250"))
                                    throw new WebException("SMTP server refused to handshake");

                                _sMTPClient.Client.Send(Encoding.ASCII.GetBytes("MAIL FROM:<" + QueryEmail + ">\r\n"));
                                sizeSMTPResponse = _sMTPClient.Client.Receive(arrSMTPResponse);
                                var mailfromResponse = Encoding.ASCII.GetString(arrSMTPResponse);
                                if (!mailfromResponse.StartsWith("250"))
                                    throw new WebException("SMTP server refused to accept mail from");

                                _sMTPClient.Client.Send(Encoding.ASCII.GetBytes("RCPT TO:<" + email + ">\r\n"));
                                sizeSMTPResponse = _sMTPClient.Client.Receive(arrSMTPResponse);
                                var rcpttoResponse = Encoding.ASCII.GetString(arrSMTPResponse);

                                _sMTPClient.Client.Send(Encoding.ASCII.GetBytes("QUIT"));   // Bye

                                _sMTPClient.Close();

                                if (!rcpttoResponse.StartsWith("250"))
                                    return false;

                                break;
                            }
                        }
                    }
                } while (true);

                return true;
            }
        }


        static void Main(string[] args)
        {
            EmailVerify emailVerify = new EmailVerify(EmailVerify.GooglePublicDNS);
            var isemailOK = emailVerify.AskDNS(domain: "microsoft.com", email: "test@microsoft.com");
        }
    }
}
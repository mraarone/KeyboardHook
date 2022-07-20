///////////////////////////////////////////////////////////////////////////////////////////////////////////
// File:            KeyboardHook.cs
//
// Initial Author:  Aaron Elliott, Director of Research & Development
// Organization:    Cyber Innovation Center, Bossier City, Louisiana
// Date:            December 1, 2013
//
// Description:     This class library implements low level keyboard hook functionality for capturing 
//                  global keyboard hook events, and tagging the events with DateTime.Now.Ticks() in 
//                  100ns time resolution.
//
// License:         This code may be modified, copied, reproduced without limitation as long as the author, 
//                  Aaron Elliott of the Cyber Innovation Center (C) 2013 is credited in code reproductions
//                  or variants.
//
// Change Log:      Date        Name/Org            Description
//                  12/1/2013   Aaron Elliott/CIC   Initial creation.
//                  12/2/2013   Aaron Elliott/CIC   Included keyboard context flags in the event handler.
//                                                  Added more inline comments.
///////////////////////////////////////////////////////////////////////////////////////////////////////////

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace ActiveAuthenticationDesktopClient
{
    public class KeyboardHook
    {
        // Create a null event templated by the KeyboardHookEventArgs class.  This points to the client's
        // custom event handler (i.e. that receives keyboard event arguments and passes them through a 
        // messaging system.
        public static event EventHandler<KeyboardHookEventArgs> KeyboardAction = null;

        // Declare LowLevelKeyboardProc to be used as a reference for the hook callback function.
        private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        // Create 'proc' the LowLevelKeyboardProc function pointer to the hook call back function.
        private static LowLevelKeyboardProc proc = HookCallback;

        // Initialize the hookId to a null pointer for error checking.
        private static IntPtr hookId = IntPtr.Zero;

        // Keyboard interrupt, used in low level user32.dll hook operations.
        private const int WH_KEYBOARD_LL = 13;

        // Low level keyboard event message identifiers.
        public enum KeyboardMessages
        {
            WM_KEYDOWN = 0x0100,
            WM_KEYUP = 0x0101,
            WM_SYSKEYDOWN = 0x0104,
            WM_SYSKEYUP = 0x0105
        }

        // Flag set for the keyboard low level hook structure describing contextual aspects of the event.
        [Flags]
        public enum KBDLLHOOKSTRUCTFlags : byte
        {
            LLKHF_EXTENDED = 0x01,
            LLKHF_INJECTED = 0x10,
            LLKHF_ALTDOWN = 0x20,
            LLKHF_UP = 0x80,
        }
        
        // Standard low level keyboard data structure format.
        [StructLayout(LayoutKind.Sequential)]
        private struct KBDLLHOOKSTRUCT
        {
            public uint VkCode;
            public uint ScanCode;
            public KBDLLHOOKSTRUCTFlags Flags;
            public uint Time;
            public IntPtr ExtraInfo;
        }

        // Hook the function into the keyboard interrupt.
        public static void Start()
        {
            using (Process curProcess = Process.GetCurrentProcess())
            {
                using (ProcessModule curModule = curProcess.MainModule)
                {
                    // Alternatively, SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle("user32"), 0); since user32.dll WILL be loaded, 
                    // its implied the current process is too.  One forum stated curModule.ModuleName will not work in .NET 4.0+ and pre Windows 8
                    // environments.  This bug has never been identified when using this method for collection.
                    hookId = SetWindowsHookEx(WH_KEYBOARD_LL, proc, GetModuleHandle(curModule.ModuleName), 0);

                    // Error checking, if hookId wasn't set by the user32.dll p/Invoke call, throw a Win32Exception error.
                    if (hookId == IntPtr.Zero)
                        throw new System.ComponentModel.Win32Exception();
                }
            }
        }

        // Unhook the function from the keyboard interrupt.
        public static void Stop()
        {
            // If a hook was successfully set, unhook it.
            if (hookId != IntPtr.Zero)
            {
                // Unhook the hook with identifier hookId.
                UnhookWindowsHookEx(hookId);

                // Reset the hook identifier.
                hookId = IntPtr.Zero;
            }
        }

        // Callback function for handling data coming from the system hook, and responsible for calling the client's custom event handler (pointed at by KeyboardAction).
        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            // Capture the current time first thing as it is closest to the event.
            long time = DateTime.Now.Ticks;

            // Prepare the characters and retrieve the keyboard state.
            byte[] lpChar = new byte[1];
            byte[] lpKeyState = new byte[256];

            // If nCode is less than zero, the hook procedure must pass the message to the CallNextHookEx function without further processing and should 
            // return the value returned by CallNextHookEx.
            if (nCode < 0)
                CallNextHookEx(hookId, nCode, wParam, lParam);
            else
            {
                // Create a new keyboard hook event argument object.
                KeyboardHookEventArgs args = new KeyboardHookEventArgs();

                // Receive the keyboard hook structure from the context parameter passed by user32.dll.
                KBDLLHOOKSTRUCT hookStruct = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));

                // wParam will only be WM_SYSKEYDOWN, WM_SYSKEYUP, WM_KEYDOWN, WM_KEYUP
                switch ((KeyboardMessages)wParam)
                {
                    // Handle all key down events the same way.
                    case KeyboardMessages.WM_SYSKEYDOWN:
                    case KeyboardMessages.WM_KEYDOWN:
                        args.KeyEvent = 1;
                        break;

                    // Handle all key up events the same way.
                    case KeyboardMessages.WM_SYSKEYUP:
                    case KeyboardMessages.WM_KEYUP:
                        args.KeyEvent = 0;
                        break;
                }

                // Set standard event arguments describing the key event.
                args.VkCode = hookStruct.VkCode;
                args.ScanCode = hookStruct.ScanCode;
                args.KeyEventTime = time;

                // Compute flag values describing the context of the key event.
                args.FlagAltDown = hookStruct.Flags.HasFlag(KBDLLHOOKSTRUCTFlags.LLKHF_ALTDOWN);
                args.FlagInjected = hookStruct.Flags.HasFlag(KBDLLHOOKSTRUCTFlags.LLKHF_INJECTED);
                args.FlagExtended = hookStruct.Flags.HasFlag(KBDLLHOOKSTRUCTFlags.LLKHF_EXTENDED);
                args.FlagUp = hookStruct.Flags.HasFlag(KBDLLHOOKSTRUCTFlags.LLKHF_UP);

                // Create an ascii representation of the vkCode using the scancode and keyboard state.
                GetKeyboardState(lpKeyState);
                ToAscii(hookStruct.VkCode, hookStruct.ScanCode, lpKeyState, lpChar, 0);
                args.AsciiCode = Convert.ToUInt32(lpChar[0]);

                // Fire the client delegate with the appropriate arguments if one is attached.
                if (KeyboardAction != null)
                    KeyboardAction(null, args);
            }

            // Bubble the message through the daisy chain of keyboard hooks.
            return CallNextHookEx(hookId, nCode, wParam, lParam);
        }

        // Unmanaged code imports for low level hook (interrupt) usage through the kernel.
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        // Unhooks message hooks.
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        // Calls the next hook in a daisy chain of hooks to bubble messages.  This is both a necessity and considered a courtesy to 
        // other system hooks.
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
        
        // This is important for identifying which module is being executed, but not necessary if 
        // statically targetting the user32 module by default.
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("user32.dll")]
        static extern int ToAscii(uint uVirtKey, uint uScanCode, byte[] lpKeyState, byte[] lpwTransKey, uint fuState);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GetKeyboardState(byte[] lpKeyState);
    }

    // Custom event argument class for data transport.
    public class KeyboardHookEventArgs : EventArgs
    {
        // This is the domain or windows security identifier for the current logged user, it is retrieved everytime a keyboard event occurs in this hook.
        public string SID //SecurityIdentifier SID
        {
            get
            {
                WindowsIdentity identity;
                identity = WindowsIdentity.GetCurrent();
                return identity.User.Value; //identity.User.AccountDomainSid;
            }
        }

        // Message values (WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP) describing the type of event that was fired.
        public uint KeyEvent   { get; set; }

        // Virtual key code (VkCode) is the virtual key value of the key associated with the event that triggered the hook.  This is not an ASCII value, but is similar.  For instance,
        // 'A' = 65 in ASCII.  However, 'A' and 'a' both = 65 in VkCodes.  Alt has a value of 160, while the ASCII character for 160 is the unprintable character for No-Break space.
        public uint VkCode     { get; set; }
        
        // Scan code is a manufacturer defined numerical identifier with respect to a physical key, usually a grid-pattern 
        // Code typically increase left to right, top to bottom of the keyboard, with variation.
        public uint ScanCode { get; set; }

        // A computed ASCII representation of the current state of a physical key pressed.  This is calculated based off of the keymapping on the keyboard, key state, scan code and vkCode,
        // an easier approach utilized the user32.dll extern, ToAscii.  This has known problems with localization, for instance, with 'dead-keys' in languages with accents, and others.  
        // ToAscii may need to be called twice if localization is a concern.
        public uint AsciiCode { get; set; }

        // DateTime.Now.Ticks value of when the keyboard hook was first fired (closest to the physical event).  The value of this property represents the number of 100-nanosecond intervals 
        // that have elapsed since 12:00:00 midnight, January 1, 0001.  Converstion to milliseconds requires a division by 10,000.  It does not include the number of ticks that are attributable 
        // to leap seconds.
        public long KeyEventTime { get; set; }

        // Flags bit 5:  The context code. The value is 1 if the ALT key is pressed; otherwise, it is 0.
        public bool FlagAltDown { get; set; }

        // Flags bit 0:  Specifies whether the key is an extended key, such as a function key or a key on the numeric keypad. The value is 1 if the key is an extended key; otherwise, it is 0.
        public bool FlagExtended { get; set; }

        // Flags bit 4:  Specifies whether the event was injected. The value is 1 if the event was injected; otherwise, it is 0.
        public bool FlagInjected { get; set; }

        // Flags bit 7:  The transition state. The value is 0 if the key is pressed and 1 if it is being released.
        public bool FlagUp { get; set; } 
    }
}

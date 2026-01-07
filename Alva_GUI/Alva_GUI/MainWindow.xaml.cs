using System;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading; // For the Timer

namespace Alva_V2_GUI
{
    public partial class MainWindow : Window
    {
        private ChatService _alva;
        private DispatcherTimer _timer;

        public MainWindow()
        {
            InitializeComponent();
            _alva = new ChatService();

            // Setup Auto-Refresh (Polling)
            // Since we aren't using WebSockets, we must ask the server for updates every few seconds.
            _timer = new DispatcherTimer();
            _timer.Interval = TimeSpan.FromSeconds(2);
            _timer.Tick += Timer_Tick;
        }

        private async void Login_Click(object sender, RoutedEventArgs e)
        {
            bool success = await _alva.Login(UserBox.Text, PassBox.Password);
            HandleAuthResult(success, "Login");
        }

        private async void Register_Click(object sender, RoutedEventArgs e)
        {
            bool success = await _alva.Register(UserBox.Text, PassBox.Password);
            HandleAuthResult(success, "Registration");
        }

        private void HandleAuthResult(bool success, string action)
        {
            if (success)
            {
                MessageBox.Show($"✅ {action} Successful! Connected as {_alva.CurrentUser}");
                _timer.Start(); // Start checking for messages
            }
            else
            {
                MessageBox.Show($"❌ {action} Failed. Check credentials or server.");
            }
        }

        // Runs every 2 seconds to check for new messages
        private async void Timer_Tick(object sender, EventArgs e)
        {
            if (!_alva.IsLoggedIn) return;

            var newMessages = await _alva.CheckInbox();
            if (newMessages.Count > 0)
            {
                foreach (var msg in newMessages)
                {
                    ChatList.Items.Add(msg);
                }
                // Scroll to bottom
                ChatList.ScrollIntoView(ChatList.Items[ChatList.Items.Count - 1]);
            }
        }

        private async void Send_Click(object sender, RoutedEventArgs e)
        {
            await SendMsg();
        }

        private async void MsgBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) await SendMsg();
        }

        private async System.Threading.Tasks.Task SendMsg()
        {
            string txt = MsgBox.Text;
            string target = RecipientBox.Text;

            if (string.IsNullOrWhiteSpace(txt)) return;

            bool sent = await _alva.SendMessage(target, txt);

            if (sent)
            {
                // Add my own message to the chat window visually
                ChatList.Items.Add(new UIMessage
                {
                    Sender = _alva.CurrentUser,
                    Content = txt,
                    Timestamp = DateTime.Now.ToString("HH:mm")
                });

                MsgBox.Clear();
                ChatList.ScrollIntoView(ChatList.Items[ChatList.Items.Count - 1]);
            }
            else
            {
                MessageBox.Show("Could not send message. User not found?");
            }
        }
    }
}
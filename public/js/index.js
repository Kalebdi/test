document.addEventListener('DOMContentLoaded', () => {
    const messageInput = document.getElementById('message-input');
    const sendBtn = document.getElementById('send-btn');
    const messagesWrapper = document.getElementById('messages-wrapper');

    async function handleChat() {
        const message = messageInput.value.trim();
        if (!message) return;

        // Tampilkan pesan user di layar
        addMessageToUI('user', message);
        messageInput.value = '';

        // Placeholder balasan AI
        const aiDiv = addMessageToUI('bot', '<span class="animate-pulse">...</span>');

        try {
            const response = await fetch('/api/chat', { // SESUAIKAN ENDPOINT API KAMU
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message })
            });

            if (!response.ok) throw new Error('Unauthorized or Server Error');

            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            aiDiv.innerHTML = ''; // Hapus loading

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                aiDiv.innerHTML += decoder.decode(value);
                // Auto scroll
                window.scrollTo(0, document.body.scrollHeight);
            }
        } catch (err) {
            aiDiv.innerHTML = "⚠️ Gagal mengirim pesan. Pastikan backend mengizinkan akses Guest.";
        }
    }

    function addMessageToUI(role, text) {
        const div = document.createElement('div');
        div.className = `p-4 mb-4 rounded-xl ${role === 'user' ? 'bg-purple-900/20 ml-auto' : 'bg-[#1a1a24] mr-auto'} max-w-[80%]`;
        div.innerHTML = text;
        messagesWrapper.appendChild(div);
        return div;
    }

    sendBtn.onclick = handleChat;
    messageInput.onkeydown = (e) => { if(e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleChat(); } };
});

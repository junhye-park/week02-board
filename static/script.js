// 삭제 전에 사용자에게 다시 확인합니다.
function confirmDelete() {
    return confirm("이 분석 기록을 정말 삭제하시겠습니까?");
}

// 입력 중인 메시지의 글자 수를 표시합니다.
const messageInput = document.getElementById("message");
const characterCount = document.getElementById("characterCount");

if (messageInput && characterCount) {
    function updateCharacterCount() {
        characterCount.textContent = `${messageInput.value.length}자`;
    }

    messageInput.addEventListener("input", updateCharacterCount);
    updateCharacterCount();
}
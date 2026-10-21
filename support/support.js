'use strict';

// Keep the native form POST so Formspree can display any required verification.
const service = document.getElementById('service');
const selectionNote = document.getElementById('selected-service');
const serviceNotes = {
  check: '現状確認は無料です。分かる範囲の情報をお知らせください。',
  update: '更新費11,000円（税込）。更新後のエラー対応を含む総額の上限は110,000円です。',
  error: '22,000円／時間（税込）。更新費11,000円を含む総額の上限は110,000円です。',
  recovery: '復旧対応は11,000円〜、最大110,000円（税込）。状況を確認してご案内します。',
  maintenance: '月額11,000円〜（税込）。対象・内容・頻度を確認してお見積りします。',
  notice: '通知へのお問い合わせに、有償サービスの購入は必要ありません。',
  other: 'ご相談の概要をお知らせください。'
};

function updateServiceNote() {
  selectionNote.textContent = serviceNotes[service.value] || '';
}

service.addEventListener('change', updateServiceNote);
document.querySelectorAll('[data-service]').forEach(link => {
  link.addEventListener('click', () => {
    const value = link.dataset.service;
    if (Object.hasOwn(serviceNotes, value)) {
      service.value = value;
      updateServiceNote();
    }
  });
});
updateServiceNote();

document.querySelectorAll('.toast-zone .alert').forEach(a=>setTimeout(()=>bootstrap.Alert.getOrCreateInstance(a).close(),6000));
const io=new IntersectionObserver(es=>es.forEach(e=>{if(e.isIntersecting){e.target.classList.add('in');io.unobserve(e.target)}}),{threshold:.12});
document.querySelectorAll('.reveal').forEach(el=>io.observe(el));
document.querySelectorAll('[data-count]').forEach(el=>{const end=+el.dataset.count,t0=performance.now();
  (function tick(t){const p=Math.min((t-t0)/1200,1);el.textContent=Math.round(end*(1-Math.pow(1-p,3)));if(p<1)requestAnimationFrame(tick)})(t0)});
document.querySelectorAll('form.needs-validation').forEach(f=>f.addEventListener('submit',e=>{
  const pw=f.querySelector('[name=password]'),cf=f.querySelector('[name=confirm]');
  if(pw&&cf)cf.setCustomValidity(pw.value===cf.value?'':'Passwords do not match');
  if(!f.checkValidity()){e.preventDefault();e.stopPropagation()}f.classList.add('was-validated')}));
const img=document.getElementById('image');
if(img)img.addEventListener('change',()=>{const f=img.files[0],p=document.getElementById('preview');if(!f)return p.classList.add('d-none');
  if(f.size>2*1024*1024){alert('Image must be under 2 MB.');img.value='';return}p.src=URL.createObjectURL(f);p.classList.remove('d-none')});

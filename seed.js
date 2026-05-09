require('dotenv').config();
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { createClient } = require('@supabase/supabase-js');
const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

async function seed() {
  const pwd = await bcrypt.hash('admin123', 10);
  const { error } = await sb.from('users').upsert(
    { id: uuidv4(), prenom: 'Admin', nom: 'Linkup', email: 'admin@linkup.ci', telephone: '+225 27 00 00 00', password: pwd, role: 'admin' },
    { onConflict: 'email' }
  );
  if (error) console.error(error);
  else console.log('Admin créé ! admin@linkup.ci / admin123');
  process.exit();
}
seed();
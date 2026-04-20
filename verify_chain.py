#!/usr/bin/env python3
"""
EU AI Act Art. 12 - Verifica integrita' della catena hash degli eventi.
Legge il database SQLite e controlla che ogni evento sia collegato
correttamente al precedente tramite hash SHA-256.
"""

import sqlite3
import hashlib
import json
import sys
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'apps/server/events.db')

def compute_expected_hash(event, prev_hash):
    """Ricalcola l'hash atteso per un evento dato l'hash precedente."""
    payload = event['payload']
    if isinstance(payload, str):
        payload = json.loads(payload)
    event_data = {
        'source_app': event['source_app'],
        'session_id': event['session_id'],
        'hook_event_type': event['hook_event_type'],
        'payload': payload,
        'timestamp': event['timestamp'],
        'model_name': event['model_name'] or '',
        'prev_hash': prev_hash,
    }
    content = json.dumps(event_data, sort_keys=True) + prev_hash
    return hashlib.sha256(content.encode()).hexdigest()

def verify_chain():
    if not os.path.exists(DB_PATH):
        print(f"Database non trovato: {DB_PATH}")
        print("Assicurati che il server sia stato avviato almeno una volta.")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Verifica che le colonne esistano
    cur.execute("PRAGMA table_info(events)")
    columns = [row['name'] for row in cur.fetchall()]
    if 'event_hash' not in columns or 'prev_hash' not in columns:
        print("ATTENZIONE: colonne event_hash/prev_hash non trovate.")
        print("Il server deve essere riavviato per applicare la migration.")
        sys.exit(1)

    cur.execute("""
        SELECT id, source_app, session_id, hook_event_type, payload,
               timestamp, model_name, event_hash, prev_hash
        FROM events
        WHERE event_hash IS NOT NULL
        ORDER BY id ASC
    """)
    events = cur.fetchall()

    if not events:
        print("Nessun evento con hash trovato nel database.")
        print("Gli eventi precedenti alle modifiche non hanno hash - e' normale.")
        sys.exit(0)

    print(f"Verifica catena su {len(events)} eventi con hash...\n")

    errors = 0
    prev_hash = '0' * 64

    for event in events:
        event_id = event['id']
        stored_hash = event['event_hash']
        stored_prev = event['prev_hash']

        # Verifica che prev_hash corrisponda all'hash precedente
        if stored_prev != prev_hash:
            print(f"[ERRORE] Evento {event_id}: prev_hash non corrisponde.")
            print(f"  Atteso:  {prev_hash}")
            print(f"  Trovato: {stored_prev}")
            errors += 1

        # Verifica che l'hash del contenuto corrisponda
        expected_hash = compute_expected_hash(dict(event), prev_hash)
        if expected_hash != stored_hash:
            print(f"[ERRORE] Evento {event_id}: contenuto manomesso.")
            print(f"  Hash atteso:  {expected_hash}")
            print(f"  Hash trovato: {stored_hash}")
            errors += 1

        prev_hash = stored_hash

    if errors == 0:
        print(f"OK - Catena integra. {len(events)} eventi verificati.")
        print("Nessuna manomissione rilevata.")
    else:
        print(f"\nATTENZIONE: {errors} anomalie rilevate nella catena.")
        print("Possibile manomissione del log.")
        sys.exit(2)

    conn.close()

if __name__ == '__main__':
    verify_chain()

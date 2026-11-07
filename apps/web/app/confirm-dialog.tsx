"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";

/**
 * In-app confirmation and text-input dialogs. Browser dialogs
 * (window.confirm/prompt) can be silenced by the browser after a few uses
 * ("Don't allow this page to create more dialogs"); they then return
 * false/null immediately and buttons appear to do nothing.
 */

type ConfirmOptions = { title: string; body?: string; confirmLabel?: string; danger?: boolean; input?: { label: string; placeholder?: string } };
type Pending = ConfirmOptions & { resolve: (value: string | null) => void };
type ConfirmApi = {
  confirm: (options: ConfirmOptions) => Promise<boolean>;
  prompt: (options: ConfirmOptions & { input: { label: string; placeholder?: string } }) => Promise<string | null>;
};

const ConfirmContext = createContext<ConfirmApi | null>(null);

export function useConfirm(): ConfirmApi {
  const api = useContext(ConfirmContext);
  if (!api) throw new Error("useConfirm must be used inside ConfirmProvider.");
  return api;
}

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<Pending | null>(null);
  const [value, setValue] = useState("");
  const dialog = useRef<HTMLDialogElement>(null);

  const open = useCallback((options: ConfirmOptions) => new Promise<string | null>((resolve) => {
    setValue("");
    setPending({ ...options, resolve });
  }), []);
  const api: ConfirmApi = {
    confirm: async (options) => (await open(options)) !== null,
    prompt: (options) => open(options),
  };

  useEffect(() => {
    if (pending && dialog.current && !dialog.current.open) dialog.current.showModal();
  }, [pending]);

  function close(result: string | null) {
    pending?.resolve(result);
    setPending(null);
    dialog.current?.close();
  }

  return (
    <ConfirmContext.Provider value={api}>
      {children}
      <dialog ref={dialog} className="confirm-dialog" onCancel={(event) => { event.preventDefault(); close(null); }} aria-labelledby="confirm-dialog-title">
        {pending && (
          <form method="dialog" onSubmit={(event) => { event.preventDefault(); if (pending.input && !value.trim()) return; close(pending.input ? value.trim() : "yes"); }}>
            <h2 id="confirm-dialog-title">{pending.title}</h2>
            {pending.body && <p>{pending.body}</p>}
            {pending.input && (
              <label className="confirm-input">
                <span>{pending.input.label}</span>
                <input autoFocus value={value} placeholder={pending.input.placeholder} onChange={(event) => setValue(event.target.value)} />
              </label>
            )}
            <div className="confirm-actions">
              <button type="button" className="button ghost" onClick={() => close(null)}>Cancel</button>
              <button type="submit" className={`button ${pending.danger ? "danger" : "primary"}`} autoFocus={!pending.input} disabled={Boolean(pending.input) && !value.trim()}>
                {pending.confirmLabel ?? "Confirm"}
              </button>
            </div>
          </form>
        )}
      </dialog>
    </ConfirmContext.Provider>
  );
}

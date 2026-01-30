;;; rawgrep.el --- Emacs integration for rawgrep -*- lexical-binding: t; -*-

;; Copyright (C) 2025

;; Author: Mark Tyrkba <marktyrkba456@gmail.com>
;; URL: https://github.com/rakivo/rawgrep
;; Version: 0.1.0
;; Package-Requires: ((emacs "24.1"))
;; Keywords: tools, grep, search

;; Permission is hereby granted, free of charge, to any person
;; obtaining a copy of this software and associated documentation
;; files (the "Software"), to deal in the Software without
;; restriction, including without limitation the rights to use, copy,
;; modify, merge, publish, distribute, sublicense, and/or sell copies
;; of the Software, and to permit persons to whom the Software is
;; furnished to do so, subject to the following conditions:

;; The above copyright notice and this permission notice shall be
;; included in all copies or substantial portions of the Software.

;; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
;; EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
;; MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
;; NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
;; BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
;; ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
;; CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
;; SOFTWARE.

;;; Commentary:
;; This package provides Emacs integration for rawgrep, a fast grep alternative.
;; It allows you to interactively search using rawgrep with jumpable results.
;;
;; Usage:
;;   M-x rawgrep
;;
;; Suggested keybinding (add to your init.el):
;;   (global-set-key (kbd "M-e") 'rawgrep)
;;
;; Or use the provided helper:
;;   (rawgrep-set-keybinding)

;;; Code:

(defgroup rawgrep nil
  "Emacs integration for rawgrep."
  :group 'tools
  :prefix "rawgrep-")

(defcustom rawgrep-executable (executable-find "rawgrep")
  "Path to the rawgrep executable."
  :type 'string
  :group 'rawgrep)

(defvar rawgrep--last-args ""
  "Last arguments used for rawgrep (pattern and flags).")

(defvar rawgrep--last-path ""
  "Last path used for rawgrep search.")

(defvar rawgrep--switch-to-path nil
  "Flag indicating user wants to switch to path editing.")

(defvar rawgrep--switch-to-args nil
  "Flag indicating user wants to switch to args editing.")

(defvar rawgrep--cancel-path nil
  "Flag indicating user cancelled path editing.")

(defvar rawgrep-args-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map minibuffer-local-map)
    (define-key map (kbd "C-;") 'rawgrep-switch-to-path)
    map)
  "Keymap for rawgrep arguments input.
Use C-; to switch to path editing.")

(defvar rawgrep-path-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map minibuffer-local-filename-completion-map)
    (define-key map (kbd "C-;") 'rawgrep-switch-to-args)
    (define-key map (kbd "C-g") 'rawgrep-cancel-path)
    map)
  "Keymap for rawgrep path input.
Use C-; to switch back to arguments editing.
Use C-g to cancel and return to arguments editing.")

(defun rawgrep-switch-to-path ()
  "Switch from arguments editing to path editing."
  (interactive)
  (setq rawgrep--switch-to-path t)
  (exit-minibuffer))

(defun rawgrep-switch-to-args ()
  "Switch from path editing to arguments editing."
  (interactive)
  (setq rawgrep--switch-to-args t)
  (exit-minibuffer))

(defun rawgrep-cancel-path ()
  "Cancel path editing and return to arguments editing."
  (interactive)
  (setq rawgrep--cancel-path t)
  (abort-recursive-edit))

(defun rawgrep ()
  "Perform rawgrep search with interactive arguments and path editing.
Enter your search pattern and any flags (e.g., 'pattern --case-sensitive -i').
Press RET to execute search.
Press C-; to switch to path editing.
While editing path:
  - Press RET or C-; to return to arguments editing
  - Press C-g to cancel path changes and return to arguments
History navigation works as usual: M-p/M-n, C-p/C-n, or up/down arrows.
Press C-g while editing arguments to cancel the search entirely."
  (interactive)
  (unless rawgrep-executable
    (error "Cannot find rawgrep executable.  Please set `rawgrep-executable'"))

  (let ((args (or rawgrep--last-args ""))
        (path default-directory)
        (done nil))

    (condition-case nil
        (progn
          ;; Arguments editing loop
          (while (not done)
            (setq rawgrep--switch-to-path nil)

            (let ((minibuffer-local-map rawgrep-args-map))
              (minibuffer-with-setup-hook
                  (lambda ()
                    ;; Move cursor to the beginning of input
                    (goto-char (minibuffer-prompt-end)))
                (setq args (read-string (format "Args (pattern and flags) (C-; for path) [path: %s]: " path)
                                        args))))

            (if rawgrep--switch-to-path
                ;; User wants to edit path
                (condition-case nil
                    (progn
                      (while rawgrep--switch-to-path
                        (setq rawgrep--switch-to-path nil
                              rawgrep--switch-to-args nil
                              rawgrep--cancel-path nil)

                        (let ((minibuffer-local-map rawgrep-path-map))
                          (setq path (read-directory-name
                                      (format "Path (RET or C-; to return to args, C-g to cancel) [args: %s]: " args)
                                      path)))

                        ;; After path editing, always return to args editing
                        ;; (whether user pressed RET or C-;)
                        (setq rawgrep--switch-to-path nil)))
                  (quit
                   ;; User pressed C-g, cancel path changes and go back to args
                   (setq rawgrep--cancel-path nil)))
              ;; User pressed RET on args, we're done
              (setq done t)))

          ;; Save for next time
          (setq rawgrep--last-args args
                rawgrep--last-path path)

          ;; Execute the search
          (let ((command (format "%s %s --jump %s"
                                 rawgrep-executable
                                 args
                                 path)))
            (grep-find command)))
      (quit
       ;; User pressed C-g on args editing, cancel everything
       (message "Rawgrep cancelled")))))

(defun rawgrep-set-keybinding ()
  "Set the suggested keybinding for rawgrep (M-e).
Users may prefer to set this manually in their init.el."
  (interactive)
  (global-set-key (kbd "M-e") 'rawgrep)
  (message "Rawgrep keybinding set: M-e"))

(provide 'rawgrep)

;;; rawgrep.el ends here

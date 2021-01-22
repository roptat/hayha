(use-modules (guix packages) (gnu packages python-xyz) (guix build-system python))

(package
  (name "python-hayha")
  (version "1.0.0")
  (source (getcwd))
  (build-system python-build-system)
  (arguments
   `(#:tests? #f))
  (inputs
   `(("python-pyyaml" ,python-pyyaml)))
  (home-page "")
  (synopsis "")
  (description "")
  (license #f))

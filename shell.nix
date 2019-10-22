with (import <nixpkgs> {});
  mkShell {
    buildInputs = (with python3Packages;
      [virtualenv cryptography
      ]);
    shellHook = ''
      unset SOURCE_DATE_EPOCH  # Required to make pip work

      VENV_PATH=.venv

      mkvirtualenv(){
        # Reset previous virtualenv
        type -t deactivate && deactivate
        rm -rf $VENV_PATH

        # Build new virtualenv with system packages
        virtualenv --system-site-packages $VENV_PATH
        source $VENV_PATH/bin/activate
        python setup.py develop
        # pip install -r requirements_dev.txt
      }

      if [[ -d $VENV_PATH ]]; then
        source $VENV_PATH/bin/activate
      else
        echo Creating new virtualenv
        mkvirtualenv
      fi
    '';
  }

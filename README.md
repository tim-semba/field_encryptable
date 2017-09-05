# FieldEncryptable

## Usage

    class SomeModel < ActiveRecord::Base
      include FieldEncryptable

      encrypt_key 'SOME KEY'
      encrypt_fields :string_field, date_field: :date
    end

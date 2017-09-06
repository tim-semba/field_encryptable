require "field_encryptable/version"

module FieldEncryptable
  extend ActiveSupport::Concern

  included do
    before_save do
      self.class
        .ancestors
        .map { |t| t.try(:attribute_target_columns) }
        .flatten.compact.uniq
        .reject(method(&:require_encrition?))
        .each do |column|
          send("encrypted_#{column}=", self.class.encryptor.encrypt_and_sign(self.instance_variable_get("@#{column}")))
          encripted!(column)
        end
    end

    def attributes
      columns = self.class.ancestors.map { |t| t.try(:attribute_target_columns) }.reject(&:nil?).flatten.uniq
      @attributes
        .to_hash
        .delete_if { |k,v| k.start_with?("encrypted_") }
        .merge(columns.map { |t| [t.to_s, self.send(t)] }.to_h)
    end

    private

    def require_encription?(column)
      instance_variable_get("@___#{column}_require_encription")
    end

    def require_encription!(column)
      instance_variable_set("@___#{column}_require_encription", true)
    end

    def encripted!(column)
      instance_variable_set("@___#{column}_require_encription", nil)
    end

    def plaintext_loaded?(column)
      instance_variable_get("@___#{column}_plaintext_loaded")
    end

    def plaintext_loaded!(column)
      instance_variable_set("@___#{column}_plaintext_loaded", true)
    end
  end

  module ClassMethods
    attr_accessor :attribute_target_columns
    attr_reader :encryptor

    def encrypt_key(key)
      @encryptor = ActiveSupport::MessageEncryptor.new(key.to_s)
    end

    def encrypt_fields(*attributes)
      self.attribute_target_columns ||= []
      attributes.each do |attr|
        if [Symbol, String].include?(attr.class)
          define_encrypted_attribute_methods(attr)
          self.attribute_target_columns << attr
        elsif attr.instance_of?(Hash)
          self.attribute_target_columns.concat(attr.keys)
          attr.each { |k,v| define_encrypted_attribute_methods(k, v) }
        end
      end

      self.attribute_target_columns.each do |attr|
        define_method("#{attr}=") do |val|
          attribute_will_change!(attr) if val != self.send(attr)
          instance_variable_set("@#{attr}", val)
          plaintext_loaded!(attr)
        end
      end
    end

    private

    def define_encrypted_attribute_methods(attr, type = :string)
      define_method("decrypt_#{attr}") do
        begin
          return instance_variable_get("@#{attr}") if plaintext_loaded?(attr)
          if new_record?
            instance_variable_set("@#{attr}", read_attribute("encrypted_#{attr}")) # load default value
            require_encription!(attr)
          else
            instance_variable_set("@#{attr}", self.class.encryptor.decrypt_and_verify(read_attribute("encrypted_#{attr}")))
          end
          plaintext_loaded!(attr)
        rescue
          nil
        end
      end

      define_method("#{attr}_was") do
        attribute_was(attr)
      end

      define_method("#{attr}_changed?") do
        attribute_changed?(attr)
      end

      define_method("#{attr}_change") do
        attribute_change(attr)
      end

      define_method(attr) do
        begin
          case type
          when :date
            self.send("decrypt_#{attr}").try(:to_date)
          when :datetime
            self.send("decrypt_#{attr}").try(:to_datetime)
          when :integer
            self.send("decrypt_#{attr}").try(:to_i)
          else
            self.send("decrypt_#{attr}")
          end
        rescue
        end
      end

      alias_method "#{attr}_before_type_cast", "decrypt_#{attr}"
    end
  end
end

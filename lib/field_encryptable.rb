require "field_encryptable/version"

module FieldEncryptable
  extend ActiveSupport::Concern

  included do
    before_save do
      attribute_target_columns.each { |a| send(a) unless plaintext_loaded?(a) } if new_record?
      columns = attribute_target_columns.select(&method(:require_encription?))
      columns.each do |column|
        send("encrypted_#{column}=", encryptor.encrypt_and_sign(instance_variable_get("@#{column}")))
        encrypted!(column)
      end
    end

    alias_method :reload_without_encrypted, :reload
    def reload(*args, &block)
      result = reload_without_encrypted(*args, &block)
      attribute_target_columns.each(&method(:reset_plaintext_loaded!))
      result
    end

    def attributes
      @attributes
        .to_hash
        .delete_if { |k,v| k.start_with?("encrypted_") }
        .merge(attribute_target_columns.map { |t| [t.to_s, self.send(t)] }.to_h)
    end

    def encryptor(cls = self.class)
      return cls.encryptor if cls.encryptor.present?
      encryptor(cls.superclass)
    rescue
      nil
    end

    def attribute_target_columns(cls = self.class)
      return cls.attribute_target_columns if cls.attribute_target_columns.present?
      attribute_target_columns(cls.superclass)
    rescue
      nil
    end

    private

    def require_encription?(column)
      instance_variable_get("@___#{column}_require_encription")
    end

    def require_encription!(column)
      instance_variable_set("@___#{column}_require_encription", true)
    end

    def encrypted!(column)
      instance_variable_set("@___#{column}_require_encription", nil)
    end

    def plaintext_loaded?(column)
      instance_variable_get("@___#{column}_plaintext_loaded")
    end

    def plaintext_loaded!(column)
      instance_variable_set("@___#{column}_plaintext_loaded", true)
    end

    def reset_plaintext_loaded!(column)
      instance_variable_set("@___#{column}_plaintext_loaded", nil)
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
          require_encription!(attr)
        end
      end
    end

    private

    def define_encrypted_attribute_methods(attr, type = :string)
      define_method("decrypt_#{attr}") do
        begin
          return instance_variable_get("@#{attr}") if plaintext_loaded?(attr)

          if new_record?
            instance_variable_set("@#{attr}", read_attribute("encrypted_#{attr}"))
            require_encription!(attr)
          else
            instance_variable_set("@#{attr}", encryptor.decrypt_and_verify(read_attribute("encrypted_#{attr}")))
          end
          plaintext_loaded!(attr)
          instance_variable_get("@#{attr}")
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

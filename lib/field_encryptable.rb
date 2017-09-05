require "field_encryptable/version"

module FieldEncryptable
  extend ActiveSupport::Concern

  included do
    before_save do
      columns = self.class.ancestors.map { |t| t.try(:attribute_target_columns) }.reject(&:nil?).flatten.uniq
      columns.each do |column|
        next if self.instance_variable_get("@___#{column}_encryption_status").blank?
        self.send("encrypted_#{column}=", self.class.encryptor.encrypt_and_sign(self.instance_variable_get("@#{column}")))
        self.instance_variable_set("@___#{column}_encryption_status", false)
      end
    end

    def attributes
      columns = self.class.ancestors.map { |t| t.try(:attribute_target_columns) }.reject(&:nil?).flatten.uniq
      @attributes
        .to_hash
        .delete_if { |k,v| k.start_with?("encrypted_") }
        .merge(columns.map { |t| [t.to_s, self.send(t)] }.to_h)
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
          self.instance_variable_set("@#{attr}", val)
          self.instance_variable_set("@___#{attr}_encryption_status", true)
        end
      end
    end

    private

    def define_encrypted_attribute_methods(attr, type = :string)
      define_method("decrypt_#{attr}") do
        begin
          return self.instance_variable_get("@#{attr}") if self.instance_variable_get("@___#{attr}_encryption_status")
          self.instance_variable_get("@#{attr}") || self.instance_variable_set("@#{attr}", self.class.encryptor.decrypt_and_verify(read_attribute("encrypted_#{attr}")))
        rescue
          val = self.persisted? ? nil : read_attribute("encrypted_#{attr}")
          self.instance_variable_get("@#{attr}") || self.instance_variable_set("@#{attr}", val)
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

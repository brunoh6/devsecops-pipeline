package main

# Contenedores de cualquier Deployment del manifiesto.
containers contains c if {
    input.kind == "Deployment"
    some c in input.spec.template.spec.containers
}

pod_spec := input.spec.template.spec

# 1. No correr como root.
deny contains msg if {
    some c in containers
    not runs_as_non_root(c)
    msg := sprintf("contenedor '%s': debe declarar runAsNonRoot: true", [c.name])
}

# 2. Sin escalada de privilegios.
deny contains msg if {
    some c in containers
    not no_privilege_escalation(c)
    msg := sprintf("contenedor '%s': allowPrivilegeEscalation debe ser false", [c.name])
}

# 3. Sistema de archivos raiz de solo lectura.
deny contains msg if {
    some c in containers
    not read_only_root(c)
    msg := sprintf("contenedor '%s': readOnlyRootFilesystem debe ser true", [c.name])
}

# 4. Quitar todas las capabilities del kernel.
deny contains msg if {
    some c in containers
    not drops_all_capabilities(c)
    msg := sprintf("contenedor '%s': securityContext.capabilities.drop debe incluir ALL", [c.name])
}

# 5. Limites de CPU y memoria.
deny contains msg if {
    some c in containers
    some r in ["cpu", "memory"]
    not has_limit(c, r)
    msg := sprintf("contenedor '%s': falta resources.limits.%s", [c.name, r])
}

# 6. Imagen con tag fijo (no latest, no vacio) o con digest.
deny contains msg if {
    some c in containers
    not image_pinned(c.image)
    msg := sprintf("contenedor '%s': la imagen '%s' debe usar un tag fijo distinto de latest", [c.name, c.image])
}

# Reglas auxiliares: cada una es verdadera solo si el campo existe Y tiene el valor seguro.
# Si el campo falta, la regla queda indefinida y el "not" del deny la cuenta como fallo.

runs_as_non_root(c) if c.securityContext.runAsNonRoot == true

runs_as_non_root(c) if {
    pod_spec.securityContext.runAsNonRoot == true
    not container_disables_non_root(c)
}

container_disables_non_root(c) if c.securityContext.runAsNonRoot == false

no_privilege_escalation(c) if c.securityContext.allowPrivilegeEscalation == false

read_only_root(c) if c.securityContext.readOnlyRootFilesystem == true

drops_all_capabilities(c) if "ALL" in c.securityContext.capabilities.drop

has_limit(c, r) if c.resources.limits[r]

image_pinned(img) if contains(img, "@sha256:")

image_pinned(img) if {
    not contains(img, "@")
    parts := split(img, "/")
    last := parts[count(parts) - 1]
    contains(last, ":")
    not endswith(last, ":latest")
}
